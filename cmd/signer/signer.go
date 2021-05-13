package main

import (
	"log"
	"net"
	"sync"
	"time"

	tmlog "github.com/tendermint/tendermint/libs/log"
	tmOS "github.com/tendermint/tendermint/libs/os"
	tmService "github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/types"
	internalSigner "github.com/tomtau/tmkms-threshold/internal/signer"
)

func signer(config internalSigner.CoConfig, logger tmlog.Logger) {
	// services to stop on shutdown
	var services []tmService.Service

	var pv types.PrivValidator

	chainID := config.ChainID
	if chainID == "" {
		log.Fatal("chain_id option is required")
	}

	local, err := internalSigner.NewLocalCosigner(config)
	if err != nil {
		panic(err)
	}
	remote, err := internalSigner.NewRemoteCosigners(config)
	if err != nil {
		panic(err)
	}

	signerServer, err := internalSigner.NewSignerServer(logger, local, config)
	if err != nil {
		panic(err)
	}
	err = signerServer.Start()
	if err != nil {
		panic(err)
	}

	services = append(services, signerServer)

	val := internalSigner.NewThresholdValidator(local, remote)
	pv = &internalSigner.PvGuard{PrivValidator: val}

	pubkey, err := pv.GetPubKey()
	if err != nil {
		log.Fatal(err)
	}
	logger.Info("Signer", "pubkey", pubkey)

	for _, node := range config.Nodes {
		dialer := net.Dialer{Timeout: 30 * time.Second}
		signer := internalSigner.NewReconnRemoteSigner(node.Address, logger, config.ChainID, pv, dialer)

		err := signer.Start()
		if err != nil {
			panic(err)
		}

		services = append(services, signer)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	tmOS.TrapSignal(logger, func() {
		for _, service := range services {
			err := service.Stop()
			if err != nil {
				panic(err)
			}
		}
		wg.Done()
	})
	wg.Wait()

}
