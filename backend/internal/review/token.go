package review

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// A review link's token names one assignment and when the link stops working, signed by
// the gateway: v1.<studio>.<assignment>.<expiry>.<mac>. It is good for that one
// assignment and nothing else. The studio and the numbers can be read by whoever holds
// the link; they cannot be changed without the key, and they open nothing by themselves.

const tokenVersion = "v1"

var b64 = base64.RawURLEncoding

func (s *Service) mac(tenant string, id, exp int64) []byte {
	h := hmac.New(sha256.New, s.cfg.Key)
	h.Write([]byte("carthago review link\x00" + tokenVersion + "\x00" + tenant + "\x00" + strconv.FormatInt(id, 10) + "\x00" + strconv.FormatInt(exp, 10)))
	return h.Sum(nil)
}

func (s *Service) sign(tenant string, id int64, expires time.Time) string {
	exp := expires.Unix()
	return strings.Join([]string{tokenVersion, b64.EncodeToString([]byte(tenant)), strconv.FormatInt(id, 36), strconv.FormatInt(exp, 36), b64.EncodeToString(s.mac(tenant, id, exp))}, ".")
}

// verify returns the studio and the assignment of a token the gateway signed that has not
// expired.
func (s *Service) verify(token string) (tenant string, id int64, ok bool) {
	if len(s.cfg.Key) == 0 || len(token) > 512 {
		return "", 0, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[0] != tokenVersion {
		return "", 0, false
	}
	t, err := b64.DecodeString(parts[1])
	if err != nil {
		return "", 0, false
	}
	id, err = strconv.ParseInt(parts[2], 36, 64)
	if err != nil || id <= 0 {
		return "", 0, false
	}
	exp, err := strconv.ParseInt(parts[3], 36, 64)
	if err != nil {
		return "", 0, false
	}
	sig, err := b64.DecodeString(parts[4])
	if err != nil || !hmac.Equal(sig, s.mac(string(t), id, exp)) {
		return "", 0, false
	}
	if !s.cfg.Now().Before(time.Unix(exp, 0)) {
		return "", 0, false
	}
	return string(t), id, true
}
