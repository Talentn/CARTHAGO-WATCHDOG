package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

type Direction uint32

const (
	ClientToServer Direction = 0
	ServerToClient Direction = 1
)

const dstAEAD = "sentinel/v1/aead"

// SealedHeaderLen is the frame type byte plus the big-endian sequence number.
const SealedHeaderLen = 1 + 8

var (
	ErrFrameMalformed = errors.New("sealed frame malformed")
	ErrFrameSeq       = errors.New("sealed frame out of sequence (replay or gap)")
	ErrFrameAuth      = errors.New("sealed frame failed authentication")
)

func aeadNonce(dir Direction, seq uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint32(n[0:4], uint32(dir))
	binary.BigEndian.PutUint64(n[4:12], seq)
	return n
}

func aeadAAD(sessionID []byte, seq uint64) []byte {
	aad := make([]byte, 0, len(dstAEAD)+len(sessionID)+SealedHeaderLen)
	aad = append(aad, dstAEAD...)
	aad = append(aad, sessionID...)
	aad = append(aad, FrameSealed)
	return binary.BigEndian.AppendUint64(aad, seq)
}

// Seal returns a complete sealed frame: 0x03 || seq (u64 BE) || ChaCha20-Poly1305(plaintext).
// Nonce = u32be(direction) || u64be(seq); AAD = dst || session_id || 0x03 || u64be(seq).
func Seal(key, sessionID []byte, dir Direction, seq uint64, plaintext []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, SealedHeaderLen, SealedHeaderLen+len(plaintext)+a.Overhead())
	out[0] = FrameSealed
	binary.BigEndian.PutUint64(out[1:], seq)
	return a.Seal(out, aeadNonce(dir, seq), plaintext, aeadAAD(sessionID, seq)), nil
}

// Open authenticates a sealed frame that must carry exactly wantSeq (strictly sequential
// per direction, so replays and gaps are both rejected).
func Open(key, sessionID []byte, dir Direction, wantSeq uint64, frame []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(frame) < SealedHeaderLen+a.Overhead() || frame[0] != FrameSealed {
		return nil, ErrFrameMalformed
	}
	seq := binary.BigEndian.Uint64(frame[1:SealedHeaderLen])
	if seq != wantSeq {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrFrameSeq, seq, wantSeq)
	}
	pt, err := a.Open(nil, aeadNonce(dir, seq), frame[SealedHeaderLen:], aeadAAD(sessionID, seq))
	if err != nil {
		return nil, ErrFrameAuth
	}
	return pt, nil
}
