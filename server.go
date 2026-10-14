package webhook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/events"
	httpclient "github.com/arandu-io/hesape/http/client"
	hwebhook "github.com/arandu-io/hesape/webhook"
)

// The prefixes of a delivery's secret reference: a stored endpoint's own
// secret, or one of Config.Server.Secrets by name.
const (
	endpointSecretRef = "endpoint:"
	namedSecretRef    = "secret:"
)

// maxFanout is how many endpoints one event reaches in one tenant.
const maxFanout = 500

// DefaultEvent is the event name of an Outgoing call that names none.
const DefaultEvent = "webhook.call"

// TestEvent is the event the test button sends.
const TestEvent = "webhook.test"

// The refusals of an Outgoing call, as webhook-server's CouldNotCallWebhook.
var (
	// ErrURLNotSet is a call with no address.
	ErrURLNotSet = errors.New("webhook: the call has no URL")
	// ErrSecretNotSet is a call with no secret to sign it with.
	ErrSecretNotSet = errors.New("webhook: the call has no secret: name one of Config.Server.Secrets with UseSecret")
	// ErrUnknownSecret is a call naming a secret the configuration does not
	// have.
	ErrUnknownSecret = errors.New("webhook: no secret of that name in Config.Server.Secrets")
	// ErrReservedHeader is an extra header the delivery writes itself.
	ErrReservedHeader = errors.New("webhook: the header is written by the delivery itself")
)

// sender is the sending side: hesape/webhook's Manager -- the durable
// delivery, the queue, the retries, the guarded transport -- under the
// endpoints this package keeps. It is the Manager's SecretProvider and the
// Publisher's resolver.
type sender struct {
	db      *data.DB
	sealer  *sealer
	manager *hwebhook.Manager
	named   map[string]string
	allowed map[string]bool
	prefix  string
}

func newSender(db *data.DB, cfg Config, seal *sealer) (*sender, error) {
	s := &sender{db: db, sealer: seal, named: map[string]string{}, prefix: cfg.Server.HeaderPrefix}
	for name, secret := range cfg.Server.Secrets {
		s.named[name] = secret
	}
	if len(cfg.Server.Events) > 0 {
		s.allowed = map[string]bool{}
		for _, name := range cfg.Server.Events {
			s.allowed[name] = true
		}
	}
	client := cfg.Server.HTTPClient
	if s.prefix != "" {
		if client == nil {
			// hesape's guarded client: its transport resolves and dials every
			// address itself, refusing private and loopback ones.
			client = httpclient.NewFactory(nil).CreatePendingRequest().CreateClient(nil)
		}
		next := client.Transport
		if next == nil {
			next = http.DefaultTransport
		}
		branded := *client
		branded.Transport = brandedHeaders{prefix: s.prefix + "-", next: next}
		client = &branded
	}
	manager, err := hwebhook.NewManager(db, s, hwebhook.ManagerOptions{
		Timeout: cfg.Server.Timeout, Retention: cfg.Server.Retention, QueueName: cfg.Server.Queue,
		UserAgent: cfg.Server.UserAgent, HTTPClient: client,
	})
	if err != nil {
		return nil, err
	}
	s.manager = manager
	return s, nil
}

// Secrets resolves a delivery's secret at the time it is sent, in the
// delivery's tenant: the hesape/webhook SecretProvider.
func (s *sender) Secrets(ctx context.Context, g security.Grant, ref string) (hwebhook.SecretSet, error) {
	if err := g.Check(hwebhook.ActionDispatch); err != nil {
		return hwebhook.SecretSet{}, err
	}
	switch {
	case strings.HasPrefix(ref, namedSecretRef):
		secret, ok := s.named[strings.TrimPrefix(ref, namedSecretRef)]
		if !ok {
			return hwebhook.SecretSet{}, ErrUnknownSecret
		}
		return hwebhook.SecretSet{Current: []byte(secret)}, nil
	case strings.HasPrefix(ref, endpointSecretRef):
		row, err := Endpoints(s.db).WhereKey(strings.TrimPrefix(ref, endpointSecretRef)).First(ctx, g)
		if err != nil {
			return hwebhook.SecretSet{}, err
		}
		if row == nil {
			return hwebhook.SecretSet{}, ErrNotFound
		}
		secret, err := s.sealer.open(row.TenantID, row.ID, "secret", row.Secret)
		if err != nil {
			return hwebhook.SecretSet{}, err
		}
		return hwebhook.SecretSet{Current: []byte(secret)}, nil
	}
	return hwebhook.SecretSet{}, fmt.Errorf("webhook: %q is not a secret reference of this package", ref)
}

// Endpoints answers which of the tenant's endpoints an event goes to: the
// hesape/webhook EndpointResolver behind the Publisher.
func (s *sender) Endpoints(ctx context.Context, g security.Grant, e events.Stored) ([]hwebhook.Endpoint, error) {
	rows, err := Endpoints(s.db).Where("active", "=", Flag(true)).OrderBy("id").Limit(maxFanout).Get(ctx, g)
	if err != nil {
		return nil, err
	}
	out := make([]hwebhook.Endpoint, 0, len(rows))
	for _, row := range rows {
		if row.Receives(e.Name) {
			out = append(out, s.target(row, []byte(e.Payload)))
		}
	}
	return out, nil
}

// target is the endpoint as a delivery is made to it. A SignerHMAC
// endpoint's signature is computed here, over the body the delivery will
// carry unchanged. A seal that does not open sends no signature and no extra
// header rather than a wrong one, and the delivery then fails in Secrets,
// where its record says so.
func (s *sender) target(row *Endpoint, body []byte) hwebhook.Endpoint {
	headers := map[string]string{}
	if row.Headers != "" {
		if plain, err := s.sealer.open(row.TenantID, row.ID, "headers", row.Headers); err == nil {
			_ = json.Unmarshal([]byte(plain), &headers)
		}
	}
	if row.Signer == SignerHMAC {
		if secret, err := s.sealer.open(row.TenantID, row.ID, "secret", row.Secret); err == nil {
			headers[row.SignatureHeader] = SignBody([]byte(secret), body)
		}
	}
	return hwebhook.Endpoint{ID: row.ID, URL: row.URL, Headers: headers, SecretRef: endpointSecretRef + row.ID}
}

// reserved reports whether an extra header is one the delivery writes.
func (s *sender) reserved(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "content-type", "content-length", "user-agent", "host":
		return true
	}
	if strings.HasPrefix(lower, "x-arandu-") {
		return true
	}
	return s.prefix != "" && strings.HasPrefix(lower, strings.ToLower(s.prefix)+"-")
}

// Outgoing is one call built in code, as webhook-server's WebhookCall:
//
//	err := webhooks.Outgoing().
//		URL("https://example.com/hooks").
//		Event("order.paid").
//		Payload(map[string]any{"order": id}).
//		UseSecret("partners").
//		Dispatch(ctx, g)
//
// Dispatch records the delivery and its queued job in one transaction; the
// worker sends it, signed, and retries it. g carries hwebhook.ActionDispatch
// for the tenant the call belongs to: the application decided to send, and
// that decision is the Grant.
type Outgoing struct {
	s       *sender
	url     string
	event   string
	id      string
	body    []byte
	secret  string
	headers map[string]string
	hmac    string
	err     error
}

// URL sets the address.
func (o *Outgoing) URL(u string) *Outgoing { o.url = u; return o }

// Event names the call. Empty means DefaultEvent.
func (o *Outgoing) Event(name string) *Outgoing { o.event = name; return o }

// UUID sets the call's identity. A call dispatched twice with one identity to
// one address is delivered once. Empty means a new one.
func (o *Outgoing) UUID(id string) *Outgoing { o.id = id; return o }

// Payload sets the body to v, encoded as JSON.
func (o *Outgoing) Payload(v any) *Outgoing {
	body, err := json.Marshal(v)
	if err != nil {
		o.err = fmt.Errorf("webhook: the payload is not JSON: %w", err)
		return o
	}
	o.body = body
	return o
}

// RawBody sets the body as it is, as webhook-server's sendRawBody. It is
// sent as application/json.
func (o *Outgoing) RawBody(body []byte) *Outgoing {
	o.body = append([]byte(nil), body...)
	return o
}

// UseSecret names the secret of Config.Server.Secrets the call is signed
// with.
func (o *Outgoing) UseSecret(name string) *Outgoing { o.secret = name; return o }

// WithHeaders adds extra headers.
func (o *Outgoing) WithHeaders(headers map[string]string) *Outgoing {
	if o.headers == nil {
		o.headers = map[string]string{}
	}
	for name, value := range headers {
		o.headers[name] = value
	}
	return o
}

// SignWithHMAC adds webhook-server's DefaultSigner signature -- the hex
// HMAC-SHA256 of the body -- in the header named, beside the Arandu one.
// Empty means DefaultSignatureHeader.
func (o *Outgoing) SignWithHMAC(header string) *Outgoing {
	if header == "" {
		header = DefaultSignatureHeader
	}
	o.hmac = header
	return o
}

// DispatchIf dispatches when cond holds, as webhook-server's dispatchIf.
func (o *Outgoing) DispatchIf(ctx context.Context, cond bool, g security.Grant) error {
	if !cond {
		return nil
	}
	return o.Dispatch(ctx, g)
}

// DispatchUnless dispatches unless cond holds.
func (o *Outgoing) DispatchUnless(ctx context.Context, cond bool, g security.Grant) error {
	return o.DispatchIf(ctx, !cond, g)
}

// Dispatch records the call and queues its delivery.
func (o *Outgoing) Dispatch(ctx context.Context, g security.Grant) error {
	if o.err != nil {
		return o.err
	}
	if strings.TrimSpace(o.url) == "" {
		return ErrURLNotSet
	}
	address, err := hwebhook.NormalizeURL(o.url)
	if err != nil {
		return err
	}
	if o.secret == "" {
		return ErrSecretNotSet
	}
	secret, ok := o.s.named[o.secret]
	if !ok {
		return ErrUnknownSecret
	}
	if len(o.headers) > MaxHeaders {
		return fmt.Errorf("webhook: a call carries at most %d extra headers", MaxHeaders)
	}
	headers := map[string]string{}
	for name, value := range o.headers {
		if o.s.reserved(name) || strings.EqualFold(name, o.hmac) {
			return fmt.Errorf("%w: %s", ErrReservedHeader, name)
		}
		headers[name] = value
	}
	body := o.body
	if body == nil {
		body = []byte("{}")
	}
	if o.hmac != "" {
		headers[o.hmac] = SignBody([]byte(secret), body)
	}
	event, id := o.event, o.id
	if event == "" {
		event = DefaultEvent
	}
	if id == "" {
		if id, err = data.NewID(); err != nil {
			return err
		}
	}
	sum := sha256.Sum256([]byte(address))
	return o.s.manager.Dispatch(ctx, g, hwebhook.Event{
		ID: id, Name: event, Payload: body, OccurredAt: time.Now().UTC(),
	}, []hwebhook.Endpoint{{
		ID: "url:" + hex.EncodeToString(sum[:16]), URL: address, Headers: headers, SecretRef: namedSecretRef + o.secret,
	}})
}

// brandedHeaders renames hesape's delivery headers to the product's prefix on
// the way out. The signature covers the timestamp, the delivery id and the
// body, never a header's name, so the rename does not change what a receiver
// verifies.
type brandedHeaders struct {
	prefix string
	next   http.RoundTripper
}

// RoundTrip sends a copy of the request with the headers renamed.
func (b brandedHeaders) RoundTrip(r *http.Request) (*http.Response, error) {
	out := r.Clone(r.Context())
	for name, values := range r.Header {
		if strings.HasPrefix(name, "X-Arandu-") {
			out.Header.Del(name)
			out.Header[http.CanonicalHeaderKey(b.prefix+strings.TrimPrefix(name, "X-Arandu-"))] = values
		}
	}
	return b.next.RoundTrip(out)
}
