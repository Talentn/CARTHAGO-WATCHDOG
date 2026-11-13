package protocol

import (
	"crypto/ed25519"
	"errors"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
)

const dstBan = "carthago/v1/ban-refusal"

// MaxBanRefLen bounds the ban reference a refusal carries.
const MaxBanRefLen = 32

// BanSigInput is the message the server identity key signs for a BanRefusal: the domain
// separator followed by the exact body bytes.
func BanSigInput(body []byte) []byte {
	return append([]byte(dstBan), body...)
}

func checkBanBody(body *pb.BanRefusalBody) error {
	if len(body.SessionId) != SessionIDLen {
		return errors.New("ban refusal: session_id must be 16 bytes")
	}
	if body.BanRef == "" || len(body.BanRef) > MaxBanRefLen {
		return errors.New("ban refusal: missing or oversized ban reference")
	}
	return nil
}

// SignBan encodes body once and signs those bytes.
func SignBan(priv ed25519.PrivateKey, kid string, body *pb.BanRefusalBody) (*pb.BanRefusal, error) {
	if err := checkBanBody(body); err != nil {
		return nil, err
	}
	b, err := proto.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &pb.BanRefusal{Body: b, ServerSig: ed25519.Sign(priv, BanSigInput(b)), ServerKeyId: kid}, nil
}

// VerifyBan checks the signature over the body bytes as received and decodes them.
func VerifyBan(pub ed25519.PublicKey, r *pb.BanRefusal) (*pb.BanRefusalBody, error) {
	if r.ServerKeyId != KeyID(pub) {
		return nil, errors.New("ban refusal: signed by another key id")
	}
	if !ed25519.Verify(pub, BanSigInput(r.Body), r.ServerSig) {
		return nil, errors.New("ban refusal: signature does not verify")
	}
	var body pb.BanRefusalBody
	if err := proto.Unmarshal(r.Body, &body); err != nil {
		return nil, err
	}
	if err := checkBanBody(&body); err != nil {
		return nil, err
	}
	return &body, nil
}
