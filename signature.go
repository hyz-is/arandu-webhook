package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/arandu-io/hesape/encryption"
	hwebhook "github.com/arandu-io/hesape/webhook"
)

// SignatureValidator decides whether a received call was signed by the
// sender that shares the receiver's secret: webhook-client's
// SignatureValidator. secrets holds the current secret and the ones still
// accepted during a rotation; body is exactly what arrived.
type SignatureValidator interface {
	Valid(r *http.Request, body []byte, secrets hwebhook.SecretSet) bool
}

// SignatureValidatorFunc adapts a function to SignatureValidator.
type SignatureValidatorFunc func(r *http.Request, body []byte, secrets hwebhook.SecretSet) bool

// Valid calls f.
func (f SignatureValidatorFunc) Valid(r *http.Request, body []byte, secrets hwebhook.SecretSet) bool {
	return f(r, body, secrets)
}

// HMAC is webhook-client's DefaultSignatureValidator: the header carries the
// hex HMAC-SHA256 of the body under the shared secret. Prefix is what comes
// before the hex, such as "sha256=" for a sender that writes one; empty means
// none.
type HMAC struct {
	Header string
	Prefix string
}

// Valid compares the header with the signature of the body under every
// accepted secret, in constant time.
func (v HMAC) Valid(r *http.Request, body []byte, secrets hwebhook.SecretSet) bool {
	header := v.Header
	if header == "" {
		header = DefaultSignatureHeader
	}
	given := strings.TrimSpace(r.Header.Get(header))
	if v.Prefix != "" {
		if !strings.HasPrefix(given, v.Prefix) {
			return false
		}
		given = strings.TrimPrefix(given, v.Prefix)
	}
	provided, err := hex.DecodeString(given)
	if err != nil || len(provided) != sha256.Size {
		return false
	}
	matched := false
	for _, secret := range allSecrets(secrets) {
		if hmac.Equal(provided, bodyMAC(secret, body)) {
			matched = true
		}
	}
	return matched
}

// DefaultTolerance is how far a signed timestamp may be from now before an
// Arandu signature is refused as a replay.
const DefaultTolerance = 5 * time.Minute

// Arandu checks hesape/webhook's scheme: the Signature, Timestamp and
// Delivery-ID headers under HeaderPrefix, sha256= over the timestamp, the
// delivery id and the body. A timestamp further than Tolerance from now is
// refused, so a captured call cannot be sent again later.
type Arandu struct {
	// HeaderPrefix is the senders' header prefix. Empty means X-Arandu.
	HeaderPrefix string
	// Tolerance is the accepted clock difference. Zero means
	// DefaultTolerance.
	Tolerance time.Duration
	// Now is the clock, replaceable by a test. Nil is time.Now.
	Now func() time.Time
}

// Valid checks the timestamp's age, then the signature.
func (v Arandu) Valid(r *http.Request, body []byte, secrets hwebhook.SecretSet) bool {
	prefix := v.HeaderPrefix
	if prefix == "" {
		prefix = "X-Arandu"
	}
	tolerance := v.Tolerance
	if tolerance == 0 {
		tolerance = DefaultTolerance
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	timestamp := r.Header.Get(prefix + "-Timestamp")
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if age := now.Sub(time.Unix(seconds, 0)); age > tolerance || age < -tolerance {
		return false
	}
	return hwebhook.Verify(secrets, timestamp, r.Header.Get(prefix+"-Delivery-ID"), body, r.Header.Get(prefix+"-Signature"))
}

// SignBody returns webhook-server's DefaultSigner signature of a body: the
// hex HMAC-SHA256 under the secret.
func SignBody(secret []byte, body []byte) string {
	return hex.EncodeToString(bodyMAC(secret, body))
}

func bodyMAC(secret, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return mac.Sum(nil)
}

func allSecrets(set hwebhook.SecretSet) [][]byte {
	out := make([][]byte, 0, len(set.Previous)+1)
	for _, secret := range append([][]byte{set.Current}, set.Previous...) {
		if len(secret) > 0 {
			out = append(out, secret)
		}
	}
	return out
}

// sealer seals an endpoint's secret and headers with a key derived from the
// application's key for this purpose alone. The sealed text carries the
// tenant, the endpoint and the purpose it was sealed for, so a value copied
// onto another row does not open there.
type sealer struct{ enc *encryption.Encrypter }

func newSealer(appKey []byte) (*sealer, error) {
	mac := hmac.New(sha256.New, appKey)
	_, _ = mac.Write([]byte("arandu-webhook:endpoint:seal:v1"))
	enc, err := encryption.NewEncrypter(mac.Sum(nil), encryption.AES256GCM)
	if err != nil {
		return nil, err
	}
	return &sealer{enc: enc}, nil
}

func sealPrefix(tenant, id, purpose string) string {
	return "webhook:v1\x00" + tenant + "\x00" + id + "\x00" + purpose + "\x00"
}

func (s *sealer) seal(tenant, id, purpose, value string) (string, error) {
	return s.enc.EncryptString(sealPrefix(tenant, id, purpose) + value)
}

// errSealedElsewhere is a sealed value opened on a row it was not sealed for.
var errSealedElsewhere = errors.New("webhook: the sealed value belongs to another endpoint")

func (s *sealer) open(tenant, id, purpose, sealed string) (string, error) {
	plain, err := s.enc.DecryptString(sealed)
	if err != nil {
		return "", err
	}
	prefix := sealPrefix(tenant, id, purpose)
	if !strings.HasPrefix(plain, prefix) {
		return "", errSealedElsewhere
	}
	return strings.TrimPrefix(plain, prefix), nil
}

// PreviousSecret is a secret that still signs after a rotation, until it
// retires.
type PreviousSecret struct {
	Secret    string    `json:"secret"`
	RetiresAt time.Time `json:"retires_at"`
}

// sealPrevious seals an endpoint's previous secrets; none seals to empty.
func (s *sealer) sealPrevious(tenant, id string, previous []PreviousSecret) (string, error) {
	if len(previous) == 0 {
		return "", nil
	}
	encoded, err := json.Marshal(previous)
	if err != nil {
		return "", err
	}
	return s.seal(tenant, id, "previous-secrets", string(encoded))
}

// openPrevious opens an endpoint's previous secrets; empty opens to none.
func (s *sealer) openPrevious(tenant, id, sealed string) ([]PreviousSecret, error) {
	if sealed == "" {
		return nil, nil
	}
	plain, err := s.open(tenant, id, "previous-secrets", sealed)
	if err != nil {
		return nil, err
	}
	var out []PreviousSecret
	if err := json.Unmarshal([]byte(plain), &out); err != nil {
		return nil, err
	}
	return out, nil
}
