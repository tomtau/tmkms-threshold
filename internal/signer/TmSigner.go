// Copyright (c) 2019 Polychain Crypto Laboratory, LLC (licensed under the Blue Oak Model License 1.0.0)
// Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)
package signer

import (
	"time"

	"github.com/tendermint/tendermint/crypto"
	tmcrypto "github.com/tendermint/tendermint/crypto/ed25519"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
)

type ThresholdValidator struct {
	threshold int

	pubkey crypto.PubKey

	// our own cosigner
	cosigner *LocalCosigner

	// peer cosigners
	peers *RemoteCosigners
}

// NewThresholdValidator creates and returns a new ThresholdValidator
func NewThresholdValidator(cosigner *LocalCosigner, peers *RemoteCosigners) *ThresholdValidator {
	validator := &ThresholdValidator{}
	validator.threshold = peers.Threshold
	validator.cosigner = cosigner
	validator.peers = peers
	validator.pubkey = tmcrypto.PubKey(cosigner.kgOutput.Shares.GroupKey().ToEd25519())
	return validator
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *ThresholdValidator) GetPubKey() (crypto.PubKey, error) {
	return pv.pubkey, nil
}

// SignVote signs a canonical representation of the vote, along with the
// chainID. Implements PrivValidator.
func (pv *ThresholdValidator) SignVote(chainID string, vote *tmProto.Vote) error {
	block := &Block{
		Height:    vote.Height,
		Round:     int64(vote.Round),
		Step:      VoteToStep(vote),
		Timestamp: vote.Timestamp,
		SignBytes: tm.VoteSignBytes(chainID, vote),
	}
	sig, stamp, err := pv.signBlock(block)

	vote.Signature = sig
	vote.Timestamp = stamp

	return err
}

// SignProposal signs a canonical representation of the proposal, along with
// the chainID. Implements PrivValidator.
func (pv *ThresholdValidator) SignProposal(chainID string, proposal *tmProto.Proposal) error {
	block := &Block{
		Height:    proposal.Height,
		Round:     int64(proposal.Round),
		Step:      ProposalToStep(proposal),
		Timestamp: proposal.Timestamp,
		SignBytes: tm.ProposalSignBytes(chainID, proposal),
	}
	sig, stamp, err := pv.signBlock(block)

	proposal.Signature = sig
	proposal.Timestamp = stamp

	return err
}

type Block struct {
	Height    int64
	Round     int64
	Step      int8
	SignBytes []byte
	Timestamp time.Time
}

func (pv *ThresholdValidator) signBlock(block *Block) ([]byte, time.Time, error) {
	stamp := block.Timestamp
	startReq := CosignerStartSessionRequest{}
	startReq.ID = pv.peers.LocalID
	startReq.PartyIDs = pv.peers.ResetParties()
	startReq.SignBytes = block.SignBytes
	resp, err := pv.cosigner.StartSession(startReq)
	if resp.MaybeSig != nil {
		return resp.MaybeSig, stamp, nil
	}
	if err != nil {
		return nil, stamp, err
	}
	otherResp, err := pv.peers.StartSession(startReq)
	if otherResp.MaybeSig != nil {
		return otherResp.MaybeSig, stamp, nil
	}
	if err != nil {
		return nil, stamp, err
	}
	msgsOut1 := make([][]byte, 0, pv.threshold+1)
	msgsOut1 = append(msgsOut1, resp.Msg1Out...)
	msgsOut1 = append(msgsOut1, otherResp.Msg1Out...)
	endReq := CosignerEndSessionRequest{}
	endReq.ID = pv.peers.LocalID
	endReq.PartyIDs = startReq.PartyIDs
	endReq.SignBytes = block.SignBytes
	endReq.Msg1Out = msgsOut1
	resp2, err := pv.cosigner.EndSession(endReq)
	if resp2.MaybeSig != nil {
		return resp2.MaybeSig, stamp, nil
	}
	if err != nil {
		return nil, stamp, err
	}
	otherResp2, err := pv.peers.EndSession(endReq)
	if otherResp2.MaybeSig != nil {
		return otherResp2.MaybeSig, stamp, nil
	}
	if err != nil {
		return nil, stamp, err
	}
	msgsOut2 := make([][]byte, 0, len(pv.peers.Clients)+1)
	msgsOut2 = append(msgsOut2, resp2.Msg2Out...)
	msgsOut2 = append(msgsOut2, otherResp2.Msg2Out...)
	hrsKey := HRSKey{
		Height: block.Height,
		Round:  block.Round,
		Step:   block.Step,
	}
	sig, err := pv.cosigner.FinalSign(hrsKey, endReq.PartyIDs, msgsOut2)
	if err != nil {
		return nil, stamp, err
	}
	sigReq := CosignerSetSignatureRequest{}
	sigReq.ID = pv.peers.LocalID
	sigReq.Sig = sig
	sigReq.SignBytes = block.SignBytes
	pv.peers.SetSignature(sigReq)
	return sig, stamp, nil
}
