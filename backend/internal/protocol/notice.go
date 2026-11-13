package protocol

import (
	"crypto/ed25519"
	"errors"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
)

const dstNotice = "carthago/v1/enforcement-notice"

const NoticeIDLen = 16

// NoticeSigInput is the message the server identity key signs for an EnforcementNotice:
// the domain separator followed by the exact body bytes.
func NoticeSigInput(body []byte) []byte {
	return append([]byte(dstNotice), body...)
}

// SignNotice encodes body once and signs those bytes.
func SignNotice(priv ed25519.PrivateKey, kid string, body *pb.EnforcementNoticeBody) (*pb.EnforcementNotice, error) {
	if len(body.NoticeId) != NoticeIDLen || len(body.SessionId) != SessionIDLen {
		return nil, errors.New("notice: notice_id and session_id must be 16 bytes")
	}
	b, err := proto.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &pb.EnforcementNotice{Body: b, ServerSig: ed25519.Sign(priv, NoticeSigInput(b)), ServerKeyId: kid}, nil
}

// VerifyNotice checks the signature over the body bytes as received and decodes them.
func VerifyNotice(pub ed25519.PublicKey, n *pb.EnforcementNotice) (*pb.EnforcementNoticeBody, error) {
	if n.ServerKeyId != KeyID(pub) {
		return nil, errors.New("notice: signed by another key id")
	}
	if !ed25519.Verify(pub, NoticeSigInput(n.Body), n.ServerSig) {
		return nil, errors.New("notice: signature does not verify")
	}
	var body pb.EnforcementNoticeBody
	if err := proto.Unmarshal(n.Body, &body); err != nil {
		return nil, err
	}
	if len(body.NoticeId) != NoticeIDLen || len(body.SessionId) != SessionIDLen {
		return nil, errors.New("notice: notice_id and session_id must be 16 bytes")
	}
	return &body, nil
}
