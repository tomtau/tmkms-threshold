// Copyright (c) 2019 Polychain Crypto Laboratory, LLC (licensed under the Blue Oak Model License 1.0.0)
// Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)
package signer

import (
	"sync"

	"github.com/tendermint/tendermint/crypto"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
)

// PvGuard guards access to an underlying PrivValidator by using mutexes
// for each of the PrivValidator interface functions
type PvGuard struct {
	PrivValidator tm.PrivValidator
	pvMutex       sync.Mutex
}

// GetPubKey implementes types.PrivValidator
func (pv *PvGuard) GetPubKey() (crypto.PubKey, error) {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.GetPubKey()
}

// SignVote implementes types.PrivValidator
func (pv *PvGuard) SignVote(chainID string, vote *tmProto.Vote) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignVote(chainID, vote)
}

// SignProposal implementes types.PrivValidator
func (pv *PvGuard) SignProposal(chainID string, proposal *tmProto.Proposal) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignProposal(chainID, proposal)
}
