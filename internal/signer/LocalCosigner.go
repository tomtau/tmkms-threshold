// Copyright (c) 2019 Polychain Crypto Laboratory, LLC (licensed under the Blue Oak Model License 1.0.0)
// Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)
package signer

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

type HRSKey struct {
	Height int64
	Round  int64
	Step   int8
}

// return true if we are less than the other key
func (hrsKey *HRSKey) Less(other HRSKey) bool {
	if hrsKey.Height < other.Height {
		return true
	}

	if hrsKey.Height > other.Height {
		return false
	}

	// height is equal, check round

	if hrsKey.Round < other.Round {
		return true
	}

	if hrsKey.Round > other.Round {
		return false
	}

	// round is equal, check step

	if hrsKey.Step < other.Step {
		return true
	}

	// everything is equal
	return false
}

type HRSMeta struct {
	state            *state.State
	output           *sign.Output
	currentSignBytes []byte
}

// LocalCosigner responds to sign requests using their share key
// The cosigner maintains a watermark to avoid double-signing
//
// LocalCosigner signing is thread saafe
type LocalCosigner struct {
	kgOutput KeyGenOutput
	// stores the last sign state for a share we have fully signed
	// incremented whenever we are asked to sign a share
	lastSignState *SignState

	// signing is thread safe
	lastSignStateMutex sync.Mutex

	sessions map[HRSKey]HRSMeta
	timeout  time.Duration
	chainId  string
}

func NewLocalCosigner(cfg CoConfig) (*LocalCosigner, error) {
	kgOutput, err := LoadKeygenOutputFromFile(cfg.KeySharePath)
	if err != nil {
		return nil, err
	}
	lastSignState, err := LoadOrCreateSignState(cfg.PrivValStateFile)
	if err != nil {
		return nil, err
	}
	cosigner := &LocalCosigner{
		kgOutput:           kgOutput,
		lastSignState:      &lastSignState,
		lastSignStateMutex: sync.Mutex{},
		sessions:           make(map[HRSKey]HRSMeta),
		timeout:            time.Duration(cfg.SessionTimeoutSec * int(time.Second)),
		chainId:            cfg.ChainID,
	}
	return cosigner, nil
}

func getPartySet(parties_arr []byte) (*party.Set, error) {
	parties := make([]party.ID, len(parties_arr))
	for i, pid := range parties_arr {
		parties[i] = party.ID(pid)
	}
	return party.NewSet(parties)
}

func (cosigner *LocalCosigner) StartSession(req CosignerStartSessionRequest) (CosignerStartSessionResponse, error) {
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()

	res := CosignerStartSessionResponse{}
	lss := cosigner.lastSignState

	height, round, step, chainId, err := UnpackHRS(req.SignBytes)
	if err != nil {
		return res, err
	}
	if chainId != cosigner.chainId {
		return res, errors.New("wrong chain ID")
	}

	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return res, err
	}

	// If the HRS is the same the sign bytes may still differ by timestamp
	// It is ok to re-sign a different timestamp if that is the only difference in the sign bytes
	if sameHRS {
		if bytes.Equal(req.SignBytes, lss.SignBytes) {
			res.MaybeSig = lss.Signature
			return res, errors.New("signed before")
		} else if _, ok := lss.OnlyDifferByTimestamp(req.SignBytes); !ok {
			return res, errors.New("mismatched data")
		}

		// same HRS, and only differ by timestamp - ok to sign again
	}
	hrsKey := HRSKey{
		Height: height,
		Round:  round,
		Step:   step,
	}
	_, ok := cosigner.sessions[hrsKey]
	if ok {
		return res, errors.New("already being signed on")
	}

	partySet, err := getPartySet(req.PartyIDs)
	if err != nil {
		return res, err
	}

	state, output, err := frost.NewSignState(partySet, cosigner.kgOutput.Secret, cosigner.kgOutput.Shares, req.SignBytes, cosigner.timeout)
	if err != nil {
		return res, err
	}
	cosigner.sessions[hrsKey] = HRSMeta{
		state:            state,
		output:           output,
		currentSignBytes: req.SignBytes,
	}
	msgs1, err := helpers.PartyRoutine(nil, state)
	if err != nil {
		delete(cosigner.sessions, hrsKey)
		return res, err
	}
	res.Msg1Out = msgs1
	return res, nil
}

func (cosigner *LocalCosigner) EndSession(req CosignerEndSessionRequest) (CosignerEndSessionResponse, error) {
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()
	res := CosignerEndSessionResponse{}
	lss := cosigner.lastSignState

	height, round, step, chainId, err := UnpackHRS(req.SignBytes)
	if err != nil {
		return res, err
	}
	if chainId != cosigner.chainId {
		return res, errors.New("wrong chain ID")
	}
	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return res, err
	}

	// If the HRS is the same the sign bytes may still differ by timestamp
	// It is ok to re-sign a different timestamp if that is the only difference in the sign bytes
	if sameHRS {
		if bytes.Equal(req.SignBytes, lss.SignBytes) {
			res.MaybeSig = lss.Signature
			return res, errors.New("signed before")
		} else if _, ok := lss.OnlyDifferByTimestamp(req.SignBytes); !ok {
			return res, errors.New("mismatched data")
		}
	}

	hrsKey := HRSKey{
		Height: height,
		Round:  round,
		Step:   step,
	}
	session, ok := cosigner.sessions[hrsKey]
	if !ok {
		return res, errors.New("invalid session")
	}

	if !bytes.Equal(req.SignBytes, session.currentSignBytes) {
		return res, errors.New("wrong signing payload")
	}

	msgs2, err := helpers.PartyRoutine(req.Msg1Out, session.state)
	if err != nil {
		delete(cosigner.sessions, hrsKey)
		return res, err
	}
	res.Msg2Out = msgs2
	return res, nil
}

func (cosigner *LocalCosigner) FinalSign(hrsKey HRSKey, msg2out [][]byte) ([]byte, error) {
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()
	session, ok := cosigner.sessions[hrsKey]
	if !ok {
		return nil, errors.New("invalid session")
	}
	_, err := helpers.PartyRoutine(msg2out, session.state)
	if err != nil {
		delete(cosigner.sessions, hrsKey)
		return nil, err
	}
	if err = session.state.WaitForError(); err != nil {
		delete(cosigner.sessions, hrsKey)
		return nil, err
	}

	cosigner.lastSignState.Height = hrsKey.Height
	cosigner.lastSignState.Round = hrsKey.Round
	cosigner.lastSignState.Step = hrsKey.Step
	cosigner.lastSignState.Signature = session.output.Signature.ToEd25519()
	cosigner.lastSignState.SignBytes = session.currentSignBytes
	cosigner.lastSignState.Save()

	for existingKey := range cosigner.sessions {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.Less(hrsKey) {
			delete(cosigner.sessions, existingKey)
		}
	}

	return cosigner.lastSignState.Signature, nil
}

func (cosigner *LocalCosigner) SetSignature(req CosignerSetSignatureRequest) (CosignerSetSignatureResponse, error) {
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()

	res := CosignerSetSignatureResponse{}
	lss := cosigner.lastSignState
	res.ID = req.ID
	height, round, step, chainId, err := UnpackHRS(req.SignBytes)
	if err != nil {
		return res, err
	}
	if chainId != cosigner.chainId {
		return res, errors.New("wrong chain ID")
	}
	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return res, err
	}

	if sameHRS {
		if bytes.Equal(req.SignBytes, lss.SignBytes) {
			return res, errors.New("signed before")
		} else {
			return res, errors.New("mismatched data")
		}
	}
	// FIXME: check signature
	if len(req.Sig) != 64 {
		return res, errors.New("incorrect signature")
	}

	cosigner.lastSignState.Height = height
	cosigner.lastSignState.Round = round
	cosigner.lastSignState.Step = step
	cosigner.lastSignState.Signature = req.Sig
	cosigner.lastSignState.SignBytes = req.SignBytes
	cosigner.lastSignState.Save()
	hrsKey := HRSKey{
		Height: height,
		Round:  round,
		Step:   step,
	}
	for existingKey := range cosigner.sessions {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.Less(hrsKey) {
			delete(cosigner.sessions, existingKey)
		}
	}
	return res, nil
}
