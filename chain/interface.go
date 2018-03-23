package chain

import (
	"sync"
	"time"

	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/btcwallet/waddrmgr"
	"github.com/roasbeef/btcwallet/wtxmgr"
)

// BackEnds returns a list of the available back ends.
// TODO: Refactor each into a driver and use dynamic registration.
func BackEnds() []string {
	return []string{
		"bitcoind",
		"btcd",
		"neutrino",
	}
}

// Interface allows more than one backing blockchain source, such as a
// btcd RPC chain server, or an SPV library, as long as we write a driver for
// it.
type Interface interface {
	Start() error
	Stop()
	WaitForShutdown()
	GetBestBlock() (*chainhash.Hash, int32, error)
	GetBlock(*chainhash.Hash) (*wire.MsgBlock, error)
	GetBlockHash(int64) (*chainhash.Hash, error)
	GetBlockHeader(*chainhash.Hash) (*wire.BlockHeader, error)
	FilterBlocks(*FilterBlocksRequest) (*FilterBlocksResponse, error)
	BlockStamp() (*waddrmgr.BlockStamp, error)
	SendRawTransaction(*wire.MsgTx, bool) (*chainhash.Hash, error)
	Rescan(*chainhash.Hash, []btcutil.Address, []*wire.OutPoint) error
	NotifyReceived([]btcutil.Address) error
	NotifyBlocks() error
	Notifications() <-chan interface{}
	BackEnd() string
}

// Notification types.  These are defined here and processed from from reading
// a notificationChan to avoid handling these notifications directly in
// rpcclient callbacks, which isn't very Go-like and doesn't allow
// blocking client calls.
type (
	// ClientConnected is a notification for when a client connection is
	// opened or reestablished to the chain server.
	ClientConnected struct{}

	// BlockConnected is a notification for a newly-attached block to the
	// best chain.
	BlockConnected wtxmgr.BlockMeta

	// FilteredBlockConnected is an alternate notification that contains
	// both block and relevant transaction information in one struct, which
	// allows atomic updates.
	FilteredBlockConnected struct {
		Block       *wtxmgr.BlockMeta
		RelevantTxs []*wtxmgr.TxRecord
	}

	FilterBlocksRequest struct {
		BlockBatch    *BlockBatch
		ExternalAddrs map[waddrmgr.ScopedIndex]btcutil.Address
		InternalAddrs map[waddrmgr.ScopedIndex]btcutil.Address
	}

	FilterBlocksResponse struct {
		BatchIndex         uint32
		BlockMeta          wtxmgr.BlockMeta
		FoundExternalAddrs map[waddrmgr.KeyScope]map[uint32]struct{}
		FoundInternalAddrs map[waddrmgr.KeyScope]map[uint32]struct{}
		RelevantTxns       []*wire.MsgTx
	}

	// BlockDisconnected is a notifcation that the block described by the
	// BlockStamp was reorganized out of the best chain.
	BlockDisconnected wtxmgr.BlockMeta

	// RelevantTx is a notification for a transaction which spends wallet
	// inputs or pays to a watched address.
	RelevantTx struct {
		TxRecord *wtxmgr.TxRecord
		Block    *wtxmgr.BlockMeta // nil if unmined
	}

	// RescanProgress is a notification describing the current status
	// of an in-progress rescan.
	RescanProgress struct {
		Hash   *chainhash.Hash
		Height int32
		Time   time.Time
	}

	// RescanFinished is a notification that a previous rescan request
	// has finished.
	RescanFinished struct {
		Hash   *chainhash.Hash
		Height int32
		Time   time.Time
	}
)

type FetchState byte

const (
	FetchStateInit FetchState = iota
	FetchStateRequested
	FetchStateFailed
	FetchStateHave
)

type MaybeBlock struct {
	BlockMeta wtxmgr.BlockMeta

	Sequence uint32

	State FetchState

	Block chan *wire.MsgBlock

	Cancel chan struct{}
}

type BlockBatch struct {
	lookAhead uint32

	mu sync.RWMutex

	sequence uint32

	knownMatches map[uint32]struct{}

	requested map[uint32]struct{}

	start uint32

	blockSema chan struct{}

	// batch contains a list of blocks that have not yet been searched for
	// recovered addresses.
	batch []*MaybeBlock
}

type Iterator struct {
	cursor uint32
}

func NewBlockBatch(batchSize uint32) *BlockBatch {
	blockSema := make(chan struct{}, 250)
	for i := 0; i < 250; i++ {
		blockSema <- struct{}{}
	}

	return &BlockBatch{
		lookAhead:    250,
		knownMatches: make(map[uint32]struct{}),
		requested:    make(map[uint32]struct{}),
		blockSema:    blockSema,
		batch:        make([]*MaybeBlock, 0, batchSize),
	}
}

func (bb *BlockBatch) Range() (uint32, uint32) {
	bb.mu.RLock()
	defer bb.mu.RUnlock()

	return bb.start, uint32(len(bb.batch))
}

func (bb *BlockBatch) AppendMaybeBlock(maybeBlock *MaybeBlock) {
	bb.mu.Lock()
	defer bb.mu.Unlock()

	maybeBlock.Sequence = bb.sequence
	bb.batch = append(bb.batch, maybeBlock)
}

func (bb *BlockBatch) GetMaybeBlock(index uint32) *MaybeBlock {
	bb.mu.RLock()
	defer bb.mu.RUnlock()

	return bb.batch[index]
}

func (bb *BlockBatch) GetBlockMeta(index uint32) wtxmgr.BlockMeta {
	bb.mu.RLock()
	defer bb.mu.RUnlock()

	maybeBlock := bb.batch[index]

	return maybeBlock.BlockMeta
}

func (bb *BlockBatch) MarkDone(index uint32) {
	bb.mu.Lock()
	defer bb.mu.Unlock()

	log.Infof("Marking block %d done", index)

	if index >= bb.start {
		bb.start = index + 1
	}
}

func (bb *BlockBatch) GetBlock(index uint32) *wire.MsgBlock {
	bb.mu.RLock()
	if index >= uint32(len(bb.batch)) {
		bb.mu.RUnlock()
		return nil
	}

	maybeBlock := bb.batch[index]
	switch maybeBlock.State {
	case FetchStateInit, FetchStateFailed:
		bb.mu.RUnlock()
		return nil
	default:
		bb.mu.RUnlock()
	}

	log.Infof("%p Receiving block %d on %v",
		maybeBlock, index, maybeBlock.Block)

	var block *wire.MsgBlock
	select {
	case block = <-maybeBlock.Block:
	case <-maybeBlock.Cancel:
	}

	select {
	case bb.blockSema <- struct{}{}:
	default:
	}

	return block
}

func (bb *BlockBatch) IsKnownMatch(index uint32) bool {
	bb.mu.RLock()
	defer bb.mu.RUnlock()

	_, ok := bb.knownMatches[index]

	return ok
}

func (bb *BlockBatch) MarkKnownMatch(index uint32) {
	bb.mu.Lock()
	defer bb.mu.Unlock()

	bb.knownMatches[index] = struct{}{}
}

func (bb *BlockBatch) ShouldPrefetch(index uint32) (bool, bool) {
	bb.mu.Lock()
	defer bb.mu.Unlock()

	if index >= uint32(len(bb.batch)) {
		return false, false
	}

	haveCapacity := uint32(len(bb.requested)) < bb.lookAhead
	if !haveCapacity {
		return false, false
	}

	_, alreadyRequested := bb.requested[index]
	if alreadyRequested {
		return false, true
	}

	maybeBlock := bb.batch[index]
	if maybeBlock.State == FetchStateHave {
		return false, true
	}

	select {
	case <-bb.blockSema:
	default:
		return false, false
	}

	maybeBlock.State = FetchStateRequested
	bb.requested[index] = struct{}{}

	stillHaveCapacity := uint32(len(bb.requested))+1 < bb.lookAhead

	return true, stillHaveCapacity
}

func (bb *BlockBatch) Receive(index uint32, seq uint32, block *wire.MsgBlock) {

	log.Infof("Received block: %d", index)

	bb.mu.Lock()
	if seq != bb.sequence {
		bb.mu.Unlock()
		log.Infof("Block %d wrong sequence", index)
		return
	}

	maybeBlock := bb.batch[index]
	if maybeBlock.State != FetchStateRequested && maybeBlock.State != FetchStateHave {
		bb.mu.Unlock()
		log.Infof("Block %d was not requested", index)
		return
	}

	delete(bb.requested, index)
	maybeBlock.State = FetchStateHave
	bb.mu.Unlock()

	log.Infof("%p Queueing block: %d on %v",
		maybeBlock, index, maybeBlock.Block)
	select {
	case maybeBlock.Block <- block:
		log.Infof("Block %d queued", index)
	case <-maybeBlock.Cancel:
		log.Infof("Block %d cancelled", index)
	}
}

func (bb *BlockBatch) Fail(index uint32, seq uint32) {

	log.Infof("Failed block: %d", index)

	bb.mu.Lock()
	if seq != bb.sequence {
		bb.mu.Unlock()
		return
	}

	maybeBlock := bb.batch[index]
	if maybeBlock.State != FetchStateRequested {
		bb.mu.Unlock()
		return
	}

	delete(bb.requested, index)
	maybeBlock.State = FetchStateFailed
	bb.mu.Unlock()

	select {
	case <-maybeBlock.Cancel:
	default:
		close(maybeBlock.Cancel)
	}
}

func (bb *BlockBatch) Size() int {
	bb.mu.RLock()
	defer bb.mu.RUnlock()

	return len(bb.batch) - int(bb.start)
}

// ResetBlockBatch resets the internal block buffer to conserve memory.
func (bb *BlockBatch) ResetBlockBatch() {
	bb.mu.Lock()
	defer bb.mu.Unlock()

	for index := range bb.knownMatches {
		delete(bb.knownMatches, index)
	}

	for index := range bb.requested {
		maybeBlock := bb.batch[index]
		select {
		case <-maybeBlock.Cancel:
		default:
			close(maybeBlock.Cancel)
		}
		delete(bb.requested, index)
	}

	bb.start = 0
	bb.batch = bb.batch[:0]

	bb.sequence++
}
