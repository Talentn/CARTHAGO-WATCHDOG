// Package protocol implements the Carthago Watchdog wire protocol primitives shared with the Rust
// client (client/crates/carthago-crypto): handshake transcript, key schedule, AEAD framing,
// device identity and session tokens. proto/README.md is the specification and
// proto/testvectors/ the golden vectors both implementations must pass.
package protocol

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const ProtocolVersion = 1

// Frame types: first byte of every WebSocket binary message.
const (
	FrameHello     byte = 0x01
	FrameChallenge byte = 0x02
	FrameSealed    byte = 0x03
)

const (
	dstTranscript   = "carthago/v1/transcript"
	dstChallengeSig = "carthago/v1/challenge-sig"
	dstProve        = "carthago/v1/prove"
	dstQuote        = "carthago/v1/quote"
	dstDeviceID     = "carthago/v1/device-id"
	infoC2S         = "carthago/v1/key/c2s"
	infoS2C         = "carthago/v1/key/s2c"
)

const (
	NonceLen     = 32
	SessionIDLen = 16
	KeyLen       = 32
)

// TranscriptHash binds the exact Hello bytes and ChallengeBody bytes:
// SHA-256(dst || u32be(len(hello)) || hello || u32be(len(body)) || body).
func TranscriptHash(hello, challengeBody []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(dstTranscript))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(hello)))
	h.Write(l[:])
	h.Write(hello)
	binary.BigEndian.PutUint32(l[:], uint32(len(challengeBody)))
	h.Write(l[:])
	h.Write(challengeBody)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// ChallengeSigInput is the message the server identity key signs (Ed25519).
func ChallengeSigInput(th [32]byte) []byte {
	return append([]byte(dstChallengeSig), th[:]...)
}

func taggedHash(dst string, th [32]byte) [32]byte {
	return sha256.Sum256(append([]byte(dst), th[:]...))
}

// ProveDigest is what the device key signs: Ed25519 signs these 32 bytes as the message,
// ECDSA P-256 signs them as the (already hashed) digest.
func ProveDigest(th [32]byte) [32]byte { return taggedHash(dstProve, th) }

// QuoteNonce is the TPM2_Quote / TPM2_Certify qualifying data for this handshake.
func QuoteNonce(th [32]byte) [32]byte { return taggedHash(dstQuote, th) }

// X25519 computes the shared secret, rejecting low-order points (all-zero output).
func X25519(priv, peerPub []byte) ([]byte, error) {
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return sk.ECDH(pk)
}

func X25519Public(priv []byte) ([]byte, error) {
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return sk.PublicKey().Bytes(), nil
}

// DeriveKeys: HKDF-SHA256(ikm = shared, salt = transcript hash), one 32-byte key per direction.
func DeriveKeys(shared []byte, th [32]byte) (c2s, s2c []byte, err error) {
	if len(shared) != 32 {
		return nil, nil, errors.New("shared secret must be 32 bytes")
	}
	prk, err := hkdf.Extract(sha256.New, shared, th[:])
	if err != nil {
		return nil, nil, err
	}
	if c2s, err = hkdf.Expand(sha256.New, prk, infoC2S, KeyLen); err != nil {
		return nil, nil, err
	}
	if s2c, err = hkdf.Expand(sha256.New, prk, infoS2C, KeyLen); err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

// DeviceID is the stable, non-reversible device identifier carried in tokens:
// hex(SHA-256(dst || alg as u8 || public key)[:16]).
func DeviceID(alg uint8, pub []byte) string {
	h := sha256.New()
	h.Write([]byte(dstDeviceID))
	h.Write([]byte{alg})
	h.Write(pub)
	return hex.EncodeToString(h.Sum(nil)[:16])
}
