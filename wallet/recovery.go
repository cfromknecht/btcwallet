package wallet

import (
	"time"

	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/btcwallet/waddrmgr"
	"github.com/roasbeef/btcwallet/wtxmgr"
)

// RecoveryManager maintains the state required to recover previously used
// addresses, and coordinates batched processing of the blocks to search.
type RecoveryManager struct {
	// recoveryWindow defines the key-derivation lookahead used when
	// attempting to recover the set of used addresses.
	recoveryWindow uint32

	// started is true after the first block has been added to the batch.
	started bool

	// blockBatch contains a list of blocks that have not yet been searched
	// for recovered addresses.
	blockBatch []wtxmgr.BlockMeta

	// state encapsulates and allocates the necessary recovery state for all
	// key scopes and subsidiary derivation paths.
	state *ScopedRecoveryState
}

func NewRecoveryManager(recoveryWindow, batchSize uint32) *RecoveryManager {
	return &RecoveryManager{
		recoveryWindow: recoveryWindow,
		blockBatch:     make([]wtxmgr.BlockMeta, 0, batchSize),
		state:          NewScopedRecoveryState(recoveryWindow),
	}
}

// AddToBlockBatch appends the block information, consisting of hash and height,
// to the batch of blocks to be searched.
func (rm *RecoveryManager) AddToBlockBatch(hash *chainhash.Hash, height int32,
	timestamp time.Time) {

	if !rm.started {
		log.Infof("Starting recovery of addresses at height=%d "+
			"hash=%x with recovery-window=%d", height, *hash,
			rm.recoveryWindow)
		rm.started = true
	}

	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: timestamp,
	}
	rm.blockBatch = append(rm.blockBatch, block)
}

// BlockBatch returns a buffer of blocks that have not yet been searched.
func (rm *RecoveryManager) BlockBatch() []wtxmgr.BlockMeta {
	return rm.blockBatch
}

// ResetBlockBatch resets the internal block buffer to conserve memory.
func (rm *RecoveryManager) ResetBlockBatch() {
	rm.blockBatch = rm.blockBatch[:0]
}

// State returns the current ScopedRecoveryState.
func (rm *RecoveryManager) State() *ScopedRecoveryState {
	return rm.state
}

// ScopedRecoveryState manages the initialization and lookup of
// AccountRecoveryStates for any actively used key scopes.
//
// In order to ensure that all addresses are properly recovered, the window
// should be sized as the sum of maximum possible inter-block and intra-block
// gap between used addresses of a particular branch.
//
// These are defined as:
//   - Inter-Block Gap: The maximum difference between the derived child indexes
//       of the last addresses used in any block and the next address consumed
//       by a later block.
//   - Intra-Block Gap: The maximum difference between the derived child indexes
//       of the first address used in any block and the last address used in the
//       same block.
type ScopedRecoveryState struct {
	// recoveryWindow defines the key-derivation lookahead used when
	// attempting to recover the set of used addresses. This value will be
	// used to instantiate a new RecoveryState for each requested scope.
	recoveryWindow uint32

	// accounts maintains a map of each requested key scope to its
	// active RecoveryState.
	accounts map[waddrmgr.KeyScope]*AccountRecoveryState
}

// NewScopedRecoveryState creates a new ScopedRecoveryState using the provided
// recoveryWindow. Each RecoveryState that is subsequently initialized for a
// particular key scope will receive the same recoveryWindow.
func NewScopedRecoveryState(recoveryWindow uint32) *ScopedRecoveryState {
	accounts := make(map[waddrmgr.KeyScope]*AccountRecoveryState)

	return &ScopedRecoveryState{
		recoveryWindow: recoveryWindow,
		accounts:       accounts,
	}
}

// StateForScope returns a AccountRecoveryState for the provided key scope. If
// one does not already exist, a new one will be generated with the
// ScopedRecoveryState's recoveryWindow.
func (rs *ScopedRecoveryState) StateForScope(
	keyScope waddrmgr.KeyScope) *AccountRecoveryState {

	// If the account recovery state already exists, return it.
	if accountState, ok := rs.accounts[keyScope]; ok {
		return accountState
	}

	// Otherwise, initialize the recovery state for this scope with the
	// chosen recovery window.
	rs.accounts[keyScope] = NewAccountRecoveryState(rs.recoveryWindow)

	return rs.accounts[keyScope]
}

// AccountRecoveryState is used to manage the recovery of addresses generated
// under a particular BIP32 account. Each account tracks both an external and
// internal branch recovery state, both of which use the same recovery window.
type AccountRecoveryState struct {
	// ExternalBranch is the recovery state of addresses generated for
	// external use, i.e. receiving addresses.
	ExternalBranch *BranchRecoveryState

	// InternalBranch is the recovery state of addresses generated for
	// internal use, i.e. change addresses.
	InternalBranch *BranchRecoveryState
}

// NewAccountRecoveryState initializes an AccountRecoveryState with the chosen
// recovery window.
func NewAccountRecoveryState(recoveryWindow uint32) *AccountRecoveryState {
	return &AccountRecoveryState{
		ExternalBranch: NewBranchRecoveryState(recoveryWindow),
		InternalBranch: NewBranchRecoveryState(recoveryWindow),
	}
}

// BranchRecoveryState maintains the required state in-order to properly
// recovery addresses derived from a particular account's internal or external
// derivation branch.
//
// A branch recovery state supports operations for:
//  - Expanding the look-ahead horizon based on which indexes have been found.
//  - Registering derived addresses with indexes within the horizon.
//  - Reporting that an address has been found.
//  - Retrieving all currently derived addresses for the branch.
//  - Looking up a particular address by its child index.
type BranchRecoveryState struct {
	// recoveryWindow defines the key-derivation lookahead used when
	// attempting to recover the set of addresses on this branch.
	recoveryWindow uint32

	// horizion records the highest child index watched by this branch.
	horizon uint32

	// lastFound maintains the highest child index that has been found
	// during recovery of this branch.
	lastFound uint32

	// addresses is a map of child index to address for all actively watched
	// addresses belonging to this branch.
	addresses map[uint32]btcutil.Address

	invalidChildren map[uint32]struct{}
}

// NewBranchRecoveryState creates a new BranchRecoveryState that can be used to
// track either the external or internal branch of an account's derivation path.
func NewBranchRecoveryState(recoveryWindow uint32) *BranchRecoveryState {
	return &BranchRecoveryState{
		recoveryWindow:  recoveryWindow,
		addresses:       make(map[uint32]btcutil.Address),
		invalidChildren: make(map[uint32]struct{}),
	}
}

// ExtendHorizon returns the current horizon and the number of addresses that
// must be derived in order to maintain the desired recovery window.
func (brs *BranchRecoveryState) ExtendHorizon() (uint32, uint32) {

	// Compute the new horizon, which should surpass our last found address
	// by the recovery window.
	curHorizon := brs.horizon

	nInvalid := brs.numInvalidInHorizon()
	minValidHorizon := brs.lastFound + brs.recoveryWindow + nInvalid

	// If the current horizon is sufficient, we will not have to derive any
	// new keys.
	if curHorizon >= minValidHorizon {
		return curHorizon, 0
	}

	// Otherwise, the number of addresses we should derive corresponds to
	// the delta of the two horizons, and we update our new horizon.
	delta := minValidHorizon - curHorizon
	brs.horizon = minValidHorizon

	return curHorizon, delta
}

// AddAddr adds a freshly derived address from our lookahead into the map of
// known addresses for this branch.
func (brs *BranchRecoveryState) AddAddr(index uint32, addr btcutil.Address) {
	brs.addresses[index] = addr
}

// GetAddr returns the address derived from a given child index.
func (brs *BranchRecoveryState) GetAddr(index uint32) btcutil.Address {
	return brs.addresses[index]
}

// ReportFound updates the last found index if the reported index exceeds the
// current value.
func (brs *BranchRecoveryState) ReportFound(index uint32) {
	if index > brs.lastFound {
		brs.lastFound = index

		for childIndex := range brs.invalidChildren {
			if childIndex < index {
				delete(brs.invalidChildren, childIndex)
			}
		}
	}
}

// MarkInvalidChild records that a particular child index results in deriving an
// invalid address. This is used to ensure that we are always have the proper
// lookahead when an invalid child is encountered.
func (brs *BranchRecoveryState) MarkInvalidChild(index uint32) {
	brs.invalidChildren[index] = struct{}{}
	brs.horizon++
}

// LastFound returns the last child index that has been recorded as found.
func (brs *BranchRecoveryState) LastFound() uint32 {
	return brs.lastFound
}

// Addrs returns a map of all currently derived child indexes to the their
// corresponding addresses.
func (brs *BranchRecoveryState) Addrs() map[uint32]btcutil.Address {
	return brs.addresses
}

func (brs *BranchRecoveryState) numInvalidInHorizon() uint32 {
	var nInvalid uint32
	for childIndex := range brs.invalidChildren {
		if brs.lastFound < childIndex && childIndex < brs.horizon {
			nInvalid++
		}
	}

	return nInvalid
}
