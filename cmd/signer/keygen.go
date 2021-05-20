package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"

	tmlog "github.com/tendermint/tendermint/libs/log"

	zmq "github.com/pebbe/zmq4"
	internalSigner "github.com/tomtau/tmkms-threshold/internal/signer"
)

func keygen(config internalSigner.CoConfig, logger tmlog.Logger) {
	n := len(config.Cosigners) + 1
	partySet := helpers.GenerateSet(party.ID(n))
	state, output, err := frost.NewKeygenState(party.ID(config.CosignerId), partySet, party.Size(config.CosignerThreshold), 0)
	if err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}
	publisher, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}
	err = publisher.Connect(config.KeygenProxyPub)
	defer publisher.Close()
	if err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}

	subscriber, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}
	err = subscriber.Connect(config.KeygenProxySub)
	if err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}
	err = subscriber.SetSubscribe("")
	if err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}
	defer subscriber.Close()

	msgsOut1 := make([][]byte, 0, n)
	msgsOut2 := make([][]byte, 0, n*(n-1)/2)
	msgsrec := map[uint16][][]byte{}

	fmt.Printf("waiting %v\n", config.CosignerId)
	time.Sleep(10 * time.Second)
	msgs1, err := helpers.PartyRoutine(nil, state)
	if err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}
	msgsrec[uint16(config.CosignerId)] = msgs1
	idbs := make([]byte, 3)
	binary.LittleEndian.PutUint16(idbs, uint16(config.CosignerId))
	idbs[2] = 0
	to_send := make([][]byte, 1, n)
	to_send[0] = idbs
	to_send = append(to_send, msgs1...)
	publisher.SendMessage(to_send)
	fmt.Printf("sent %v\n", config.CosignerId)
	received := 1
	for received < n {
		msg, err := subscriber.RecvMessageBytes(0)
		if err != nil {
			logger.Error(
				"Tendermint Validator",
				"keygen",
				err,
			)
			return
		}
		fmt.Printf("received %v msg %v\n", config.CosignerId, msg)
		nodeId := binary.LittleEndian.Uint16(msg[0])
		round := msg[0][2]
		if _, ok := msgsrec[nodeId]; !ok && round == 0 {
			msgsrec[nodeId] = msg[1:]
			received++
		} else {
			fmt.Printf("skip %v msg\n", config.CosignerId)
		}
	}
	for i := range msgsrec {
		msgsOut1 = append(msgsOut1, msgsrec[uint16(i)]...)
	}

	msgs2, err := helpers.PartyRoutine(msgsOut1, state)
	if err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}
	msgsrec = map[uint16][][]byte{}
	msgsrec[uint16(config.CosignerId)] = msgs2
	idbs[2] = 1
	to_send = make([][]byte, 1, n)
	to_send[0] = idbs
	to_send = append(to_send, msgs2...)
	publisher.SendMessage(to_send)
	fmt.Printf("sent %v\n", config.CosignerId)
	received = 1
	for received < n {
		msg, err := subscriber.RecvMessageBytes(0)
		if err != nil {
			logger.Error(
				"Tendermint Validator",
				"keygen",
				err,
			)
			return
		}
		fmt.Printf("received %v msg %v\n", config.CosignerId, msg)
		nodeId := binary.LittleEndian.Uint16(msg[0])
		round := msg[0][2]
		if _, ok := msgsrec[nodeId]; !ok && round == 1 {
			msgsrec[nodeId] = msg[1:]
			received++
		} else {
			fmt.Printf("skip %v msg\n", config.CosignerId)
		}
	}
	for i := range msgsrec {
		msgsOut2 = append(msgsOut2, msgsrec[uint16(i)]...)
	}

	_, err = helpers.PartyRoutine(msgsOut2, state)
	if err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}

	if err = state.WaitForError(); err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}
	public := output.Public
	groupKey := public.GroupKey()
	logger.Info(
		"Tendermint Validator",
		"group key",
		groupKey.ToEd25519(),
	)
	if err = state.WaitForError(); err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}
	shareSecret := output.SecretKey

	kgOutput := internalSigner.KeyGenOutput{
		Secret: shareSecret,
		Shares: public,
	}

	var jsonData []byte
	jsonData, err = json.MarshalIndent(kgOutput, "", " ")
	if err != nil {
		logger.Error(
			"Tendermint Validator",
			"keygen",
			err,
		)
		return
	}

	_ = ioutil.WriteFile(config.KeySharePath, jsonData, 0644)
	logger.Info(
		"Tendermint Validator",
		"Success: output written to",
		config.KeySharePath,
	)

}
