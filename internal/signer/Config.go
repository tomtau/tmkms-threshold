// Copyright (c) 2019 Polychain Crypto Laboratory, LLC (licensed under the Blue Oak Model License 1.0.0)
// Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)
package signer

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"

	"github.com/BurntSushi/toml"
)

type NodeConfig struct {
	Address string `toml:"address"`
}

type CosignerConfig struct {
	ID      int    `toml:"id"`
	Address string `toml:"remote_address"`
}

func LoadConfigFromFile(file string) (CoConfig, error) {
	var config CoConfig

	reader, err := os.Open(file)
	if err != nil {
		return config, err
	}
	_, err = toml.DecodeReader(reader, &config)
	return config, err
}

type CoConfig struct {
	KeySharePath      string `toml:"key_share_file"`
	PrivValStateFile  string `toml:"state_file"`
	ChainID           string `toml:"chain_id"`
	CosignerId        byte   `toml:"cosigner_id"`
	CosignerThreshold byte   `toml:"cosigner_threshold"`
	KeygenProxyPub    string `toml:"keygen_proxy_pub"`
	KeygenProxySub    string `toml:"keygen_proxy_sub"`
	SessionTimeoutSec int    `toml:"session_timeout_sec"`

	ListenAddress string           `toml:"cosigner_listen_address"`
	Nodes         []NodeConfig     `toml:"node"`
	Cosigners     []CosignerConfig `toml:"cosigner"`
}

type KeyGenOutput struct {
	Secret *eddsa.SecretShare
	Shares *eddsa.Public
}

func LoadKeygenOutputFromFile(file string) (KeyGenOutput, error) {
	var kgOutput KeyGenOutput

	var jsonData []byte
	jsonData, err := ioutil.ReadFile(file)
	if err != nil {
		return kgOutput, err
	}
	err = json.Unmarshal(jsonData, &kgOutput)
	if err != nil {
		return kgOutput, err
	}
	return kgOutput, nil
}
