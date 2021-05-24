package signer

type CosignerStartSessionRequest struct {
	ID        byte
	SignBytes []byte
	PartyIDs  []byte
}

type CosignerStartSessionResponse struct {
	Msg1Out  [][]byte
	MaybeSig []byte
}

type CosignerEndSessionRequest struct {
	ID        byte
	SignBytes []byte
	PartyIDs  []byte
	Msg1Out   [][]byte
}

type CosignerEndSessionResponse struct {
	Msg2Out  [][]byte
	MaybeSig []byte
}

type CosignerSetSignatureRequest struct {
	ID        byte
	SignBytes []byte
	Sig       []byte
}

type CosignerSetSignatureResponse struct {
	ID byte
}

type CosignerRequest interface {
	PartyId() byte
}

func (req CosignerStartSessionRequest) PartyId() byte {
	return req.ID
}

func (req CosignerEndSessionRequest) PartyId() byte {
	return req.ID
}

func (req CosignerSetSignatureRequest) PartyId() byte {
	return req.ID
}

func MsgToRequest(msg [][]byte) CosignerRequest {
	if len(msg) < 3 {
		return nil
	}
	if len(msg[0]) < 2 {
		return nil
	}
	if len(msg[1]) == 0 || len(msg[2]) == 0 {
		return nil
	}
	roundt := msg[0][0]
	partyId := msg[0][1]
	switch roundt {
	case 0:
		req := CosignerStartSessionRequest{}
		req.SignBytes = msg[1]
		req.PartyIDs = msg[2]
		req.ID = partyId
		return req
	case 1:
		req := CosignerEndSessionRequest{}
		req.SignBytes = msg[1]
		req.PartyIDs = msg[2]
		req.Msg1Out = msg[3:]
		req.ID = partyId
		return req
	case 2:
		req := CosignerSetSignatureRequest{}
		req.SignBytes = msg[1]
		req.Sig = msg[2]
		req.ID = partyId
		return req
	default:
		return nil
	}
}

// Cosigner interface is a set of methods for an m-of-n threshold signature.
// This interface abstracts the underlying key storage and management
type Cosigner interface {
	// Start signing session
	StartSession(req CosignerStartSessionRequest) (CosignerStartSessionResponse, error)

	// Final round
	EndSession(req CosignerEndSessionRequest) (CosignerEndSessionResponse, error)

	// Set the provided signature
	SetSignature(req CosignerSetSignatureRequest) (CosignerSetSignatureResponse, error)
}
