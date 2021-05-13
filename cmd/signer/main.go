package main

import (
	"encoding/base64"

	"flag"
	"fmt"
	"log"
	"os"

	"github.com/enigmampc/btcutil/bech32"
	tmcrypto "github.com/tendermint/tendermint/crypto/ed25519"
	tmlog "github.com/tendermint/tendermint/libs/log"
	internalSigner "github.com/tomtau/tmkms-threshold/internal/signer"
)

// ConvertAndEncode converts from a base64 encoded byte string to base32 encoded byte string and then to bech32.
// Copyright (c) 2016-2021 All in Bits, Inc (licensed under the Apache License, Version 2.0)
// Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)
func ConvertAndEncode(hrp string, data []byte) (string, error) {
	prefixed_data := []byte{0x16, 0x24, 0xDE, 0x64, 0x20}
	prefixed_data = append(prefixed_data, data...)
	converted, err := bech32.ConvertBits(prefixed_data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("encoding bech32 failed: %w", err)
	}

	return bech32.Encode(hrp, converted)
}

func main() {
	logger := tmlog.NewTMLogger(
		tmlog.NewSyncWriter(os.Stdout),
	).With("module", "validator")

	var configFile = flag.String("config", "", "path to configuration file")
	var pubkeyhrp = flag.String("pubkeyhrp", "", "pubkey bech32 prefix (if any)")

	flag.Parse()
	var command = flag.Arg(0)

	if *configFile == "" {
		panic("--config flag is required")
	}
	if command == "" {
		panic("missing command (keygen|sign)")
	}

	config, err := internalSigner.LoadConfigFromFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	logger.Info(
		"Tendermint Validator",
		"p2p priv-key", config.KeySharePath,
		"priv-state-dir", config.PrivValStateFile,
	)

	switch command {
	case "sign":
		signer(config, logger)
	case "keygen":
		keygen(config, logger)
	case "print-pubkey":
		kgOutput, err := internalSigner.LoadKeygenOutputFromFile(config.KeySharePath)
		if err != nil {
			log.Fatal(err)
		}
		groupKey := tmcrypto.PubKey(kgOutput.Shares.GroupKey().ToEd25519())

		if *pubkeyhrp == "" {
			pubStr := base64.StdEncoding.EncodeToString(groupKey.Bytes())
			fmt.Printf("pubkey: %s\n", pubStr)
			nodeId := groupKey.Address()
			fmt.Printf("address: %s\n", nodeId)
		} else {
			pubStr, err := ConvertAndEncode(*pubkeyhrp, groupKey.Bytes())
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("pubkey: %s\n", pubStr)

		}

	default:
		logger.Error(
			"Tendermint Validator",
			"unknown command",
		)
	}

}
