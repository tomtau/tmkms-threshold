// Copyright (c) 2019 Polychain Crypto Laboratory, LLC (licensed under the Blue Oak Model License 1.0.0)
// Modifications Copyright (c) 2021, Foris Limited (licensed under the Apache License, Version 2.0)
package signer

import (
	"fmt"

	tmlog "github.com/tendermint/tendermint/libs/log"

	zmq "github.com/pebbe/zmq4"
	tmService "github.com/tendermint/tendermint/libs/service"
)

// SignerServer listens on zmq and responds to any
// signature requests its socket.
type SignerServer struct {
	tmService.BaseService
	Context *zmq.Context
	Server  *zmq.Socket
	Local   *LocalCosigner
}

// NewSignerServer instantiates a local cosigner with the specified key and sign state
func NewSignerServer(logger tmlog.Logger, local *LocalCosigner, config CoConfig) (*SignerServer, error) {
	context, err := zmq.NewContext()
	if err != nil {
		return nil, err
	}
	server, err := context.NewSocket(zmq.REP)
	if err != nil {
		return nil, err
	}
	err = server.Bind(config.ListenAddress)
	if err != nil {
		return nil, err
	}
	cosignerServer := &SignerServer{
		Context: context,
		Server:  server,
		Local:   local,
	}

	cosignerServer.BaseService = *tmService.NewBaseService(logger, "SignerServer", cosignerServer)
	return cosignerServer, nil
}

// OnStart implements cmn.Service.
func (rs *SignerServer) OnStart() error {
	rs.BaseService.OnStart()
	go rs.loop()
	return nil
}

// OnStop implements cmn.Service.
func (rs *SignerServer) OnStop() {
	rs.BaseService.OnStop()
	rs.Server.SetLinger(0)
	rs.Server.Close()
	rs.Context.Term()
}

// main loop for SignerServer
func (rs *SignerServer) loop() {
	for {
		msg, err := rs.Server.RecvMessageBytes(0)
		req := MsgToRequest(msg)
		if err == nil && req != nil {
			switch v := req.(type) {
			case CosignerSetSignatureRequest:
				_, err = rs.Local.SetSignature(v)
				rs.Logger.Debug("got setsig", v)
				to_send := make([][]byte, 2)
				if err != nil {
					rs.Logger.Debug("setsig err", err)
					to_send[0] = []byte("error")
					to_send[1] = []byte(fmt.Sprintf("err: %v", err))
				} else {
					rs.Logger.Debug("setsig ok")
					ok := []byte("ok")
					to_send[0] = ok
					to_send[1] = ok
				}
				_, err = rs.Server.SendMessage(to_send)
				if err != nil {
					rs.Logger.Error(
						"send setsig reply",
						err,
					)
				}
			case CosignerEndSessionRequest:
				resp, err := rs.Local.EndSession(v)
				rs.Logger.Debug("got end session", v)
				to_send := make([][]byte, 2)
				if resp.MaybeSig != nil {
					rs.Logger.Debug("got endsession sig", resp.MaybeSig)
					to_send[0] = []byte("signature")
					to_send[1] = resp.MaybeSig
				} else if err != nil {
					rs.Logger.Debug("got endsession error", err)
					to_send[0] = []byte("error")
					to_send[1] = []byte(fmt.Sprintf("err: %v", err))
				} else {
					rs.Logger.Debug("endsession ok", resp.Msg2Out)
					to_send = resp.Msg2Out
				}
				_, err = rs.Server.SendMessage(to_send)
				if err != nil {
					rs.Logger.Error(
						"send endsession reply",
						err,
					)
				}
			case CosignerStartSessionRequest:
				resp, err := rs.Local.StartSession(v)
				rs.Logger.Debug("got start session", v)
				to_send := make([][]byte, 2)
				if resp.MaybeSig != nil {
					rs.Logger.Debug("got startsession sig", resp.MaybeSig)
					to_send[0] = []byte("signature")
					to_send[1] = resp.MaybeSig
				} else if err != nil {
					rs.Logger.Debug("got startsession error", err)
					to_send[0] = []byte("error")
					to_send[1] = []byte(fmt.Sprintf("err: %v", err))
				} else {
					rs.Logger.Debug("startsession ok", resp.Msg1Out)
					to_send = resp.Msg1Out
				}
				_, err = rs.Server.SendMessage(to_send)
				if err != nil {
					rs.Logger.Error(
						"send startsession reply",
						err,
					)
				}
			default:
				to_send := make([][]byte, 2)
				to_send[0] = []byte("error")
				to_send[1] = []byte("unknown request type")
				_, err = rs.Server.SendMessage(to_send)
				if err != nil {
					rs.Logger.Error(
						"send error reply",
						err,
					)
				}
			}
		} else {
			rs.Logger.Error(
				"receive bytes error",
				err, msg,
			)
			to_send := make([][]byte, 2)
			to_send[0] = []byte("error")
			to_send[1] = []byte(fmt.Sprintf("err: %v", err))
			_, err = rs.Server.SendMessage(to_send)
			if err != nil {
				rs.Logger.Error(
					"send error reply",
					err,
				)
			}
		}
	}
}
