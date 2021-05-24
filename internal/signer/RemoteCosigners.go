package signer

import (
	"bytes"
	"errors"
	"time"

	zmq "github.com/pebbe/zmq4"
)

// RemoteCosigners maintains the connections to the remote nodes
// and collects responses from them
//
// NOT thread safe
type RemoteCosigners struct {
	Context        *zmq.Context
	Clients        map[*zmq.Socket]byte
	ActiveClients  map[*zmq.Socket]byte
	SessionClients map[*zmq.Socket]byte
	Poller         *zmq.Poller
	LocalID        byte
	Threshold      int
	timeout        time.Duration
}

func NewRemoteCosigners(cfg CoConfig) (*RemoteCosigners, error) {
	context, err := zmq.NewContext()
	if err != nil {
		return nil, err
	}
	var poller *zmq.Poller = zmq.NewPoller()
	clients := make(map[*zmq.Socket]byte)
	activeClients := make(map[*zmq.Socket]byte)
	sessionClients := make(map[*zmq.Socket]byte)
	for _, cosigner := range cfg.Cosigners {
		// FIXME: close clients on shutdown
		client, err := context.NewSocket(zmq.REQ)
		if err != nil {
			return nil, err
		}
		client.Connect(cosigner.Address)
		poller.Add(client, zmq.POLLIN)
		clients[client] = byte(cosigner.ID)
		activeClients[client] = byte(cosigner.ID)
	}
	cosigner := &RemoteCosigners{
		Context:        context,
		Clients:        clients,
		ActiveClients:  activeClients,
		SessionClients: sessionClients,
		Poller:         poller,
		LocalID:        cfg.CosignerId,
		Threshold:      int(cfg.CosignerThreshold),
		timeout:        time.Duration(cfg.SessionTimeoutSec * int(time.Second)),
	}
	return cosigner, nil
}

func (cosigners *RemoteCosigners) ResetParties() []byte {
	parties_arr := make([]byte, cosigners.Threshold+1)

	if len(cosigners.ActiveClients) < cosigners.Threshold {
		for k, v := range cosigners.Clients {
			cosigners.ActiveClients[k] = v
		}
		polled, _ := cosigners.Poller.Poll(cosigners.timeout)

		for _, item := range polled {
			if item.Events&zmq.POLLIN != 0 {
				item.Socket.RecvMessageBytes(0)
			}
		}
	}
	cosigners.SessionClients = make(map[*zmq.Socket]byte)
	i := 0
	for socket, partyI := range cosigners.ActiveClients {
		parties_arr[i] = partyI
		cosigners.SessionClients[socket] = partyI
		i++
		if i == cosigners.Threshold {
			break
		}
	}
	parties_arr[cosigners.Threshold] = cosigners.LocalID

	return parties_arr
}

func (cosigners *RemoteCosigners) StartSession(req CosignerStartSessionRequest) (CosignerStartSessionResponse, error) {
	msgsOut1 := make([][]byte, 0, cosigners.Threshold)
	res := CosignerStartSessionResponse{}
	to_send := make([][]byte, 3)
	to_send[0] = []byte("xx")
	to_send[0][0] = 0
	to_send[0][1] = req.ID
	to_send[1] = req.SignBytes
	to_send[2] = req.PartyIDs

	for client := range cosigners.SessionClients {
		_, err := client.SendMessage(to_send)
		if err != nil {
			delete(cosigners.ActiveClients, client)
		}
	}
	polled, err := cosigners.Poller.Poll(cosigners.timeout)
	if err != nil {
		return res, err
	}
	var collected = 1
	for _, item := range polled {
		if item.Events&zmq.POLLIN != 0 {
			reply, err := item.Socket.RecvMessageBytes(0)
			_, ok := cosigners.SessionClients[item.Socket]
			if err == nil && !bytes.Equal(reply[0], []byte("error")) && ok {
				if bytes.Equal(reply[0], []byte("signature")) {
					res.MaybeSig = reply[1]
				} else {
					collected += 1
					msgsOut1 = append(msgsOut1, reply...)
				}
			}
			if err != nil {
				delete(cosigners.ActiveClients, item.Socket)
			}
		}
	}
	res.Msg1Out = msgsOut1
	if len(res.MaybeSig) == 64 {
		// FIXME: verify sig
		return res, errors.New("signed before")
	} else if collected < cosigners.Threshold {
		return res, errors.New("not enough messages collected")
	}
	return res, nil
}

func (cosigners *RemoteCosigners) EndSession(req CosignerEndSessionRequest) (CosignerEndSessionResponse, error) {
	n := len(cosigners.Clients) + 1
	msgsOut2 := make([][]byte, 0, n)
	res := CosignerEndSessionResponse{}

	to_send := make([][]byte, 3, n)
	to_send[0] = []byte("xx")
	to_send[0][0] = 1
	to_send[0][1] = req.ID
	to_send[1] = req.SignBytes
	to_send[2] = req.PartyIDs

	to_send = append(to_send, req.Msg1Out...)
	for client := range cosigners.SessionClients {
		_, err := client.SendMessage(to_send)
		if err != nil {
			delete(cosigners.ActiveClients, client)
		}
	}
	polled, err := cosigners.Poller.Poll(cosigners.timeout)

	if err != nil {
		return res, err
	}
	var collected = 1
	for _, item := range polled {
		if item.Events&zmq.POLLIN != 0 {
			reply, err := item.Socket.RecvMessageBytes(0)
			_, ok := cosigners.SessionClients[item.Socket]
			if err == nil && !bytes.Equal(reply[0], []byte("error")) && ok {
				if bytes.Equal(reply[0], []byte("signature")) {
					res.MaybeSig = reply[1]
				} else {
					collected += 1
					msgsOut2 = append(msgsOut2, reply...)
				}
			}
			if err != nil {
				delete(cosigners.ActiveClients, item.Socket)
			}
		}
	}
	res.Msg2Out = msgsOut2
	if len(res.MaybeSig) == 64 {
		// FIXME: verify sig
		return res, errors.New("signed before")
	} else if collected < cosigners.Threshold {
		return res, errors.New("not enough messages collected")
	}
	return res, nil
}

func (cosigners *RemoteCosigners) SetSignature(req CosignerSetSignatureRequest) (CosignerSetSignatureResponse, error) {
	res := CosignerSetSignatureResponse{}
	to_send := make([][]byte, 3)
	to_send[0] = []byte("xx")
	to_send[0][0] = 2
	to_send[0][1] = req.ID
	to_send[1] = req.SignBytes
	to_send[2] = req.Sig
	for client := range cosigners.ActiveClients {
		_, err := client.SendMessage(to_send)
		if err != nil {
			delete(cosigners.ActiveClients, client)
		}
	}
	polled, _ := cosigners.Poller.Poll(cosigners.timeout)

	for _, item := range polled {
		if item.Events&zmq.POLLIN != 0 {
			_, err := item.Socket.RecvMessageBytes(0)

			if err != nil {
				delete(cosigners.ActiveClients, item.Socket)
			}
		}
	}
	res.ID = req.ID
	return res, nil
}
