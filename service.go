package webhook

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/framework/validation"
	hwebhook "github.com/arandu-io/hesape/webhook"
)

// Pagination bounds for the listings. A request that asks for everything gets
// the maximum, never everything.
const (
	defaultLimit = 50
	maxLimit     = 200
)

// DefaultRotationOverlap is how long a rotated secret keeps signing beside
// the new one when the management route rotates it: a day, because
// installing a secret is a deploy on the receiver's side.
const DefaultRotationOverlap = 24 * time.Hour

// EndpointRequest is an endpoint as a form or a client sends it.
//
// There is no TenantID here and there must never be one: the tenant comes
// from the Grant, which comes from the session.
type EndpointRequest struct {
	Name string
	URL  string
	// Events are the event names it receives; AllEvents receives every one.
	Events []string
	// Dialect is DialectArandu (empty means it, unless Signer names one),
	// DialectHMAC or DialectStandardWebhooks.
	Dialect string
	// Signer is the previous release's name of Dialect, read when Dialect is empty.
	Signer string
	// SignatureHeader is where a DialectHMAC signature goes. Empty means
	// DefaultSignatureHeader.
	SignatureHeader string
	// WithoutAranduHeaders sends a DialectHMAC call with its signature
	// header alone, without the Arandu signature, timestamp and delivery id.
	WithoutAranduHeaders bool
	// Headers is "Name: value" per line. On an update, empty keeps the stored
	// headers, which are never shown back.
	Headers string
	Active  bool
	// Policy is the endpoint's own delivery policy. Nil follows Server.Policy
	// on a create, and keeps what the endpoint has on an update.
	Policy *Policy
	// ResetPolicy, on an update, drops the endpoint's own policy, so it
	// follows Server.Policy again.
	ResetPolicy bool
}

// ImportRequest is an endpoint an application already keeps elsewhere,
// stored with the id and the secrets it has, so the receivers notice nothing.
type ImportRequest struct {
	// ID is kept as the endpoint's id: up to 64 letters, digits, '_', '.',
	// ':' and '-'.
	ID string
	EndpointRequest
	// Secret is the current signing secret, kept as it is: whsec_ and the
	// standard base64 of the key for DialectStandardWebhooks, at least
	// MinSecretBytes for the others.
	Secret string
	// PreviousSecrets still sign until each retires; the ones already
	// retired are dropped.
	PreviousSecrets []PreviousSecret
	// CreatedAt is when the endpoint was created where it comes from. Zero
	// means now.
	CreatedAt time.Time
	// ConsecutiveFailures is how many of its deliveries in a row gave up
	// where it comes from, so DisableAfter counts on from there.
	ConsecutiveFailures int
	// DisabledAt and DisabledReason are when and why it was turned off where
	// it comes from -- DisabledByFailures, or the reason a person gave. Either
	// needs the other, and both need Active false.
	DisabledAt     *time.Time
	DisabledReason string
}

// MaxDisabledReason is the longest reason an endpoint is turned off with.
const MaxDisabledReason = 64

// validReason reports whether a reason for turning an endpoint off can be
// kept: one line of printable text, at most MaxDisabledReason bytes.
func validReason(reason string) bool {
	if len(reason) > MaxDisabledReason || strings.TrimSpace(reason) != reason {
		return false
	}
	for _, r := range reason {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// The refusals of the endpoint use cases that are not a policy's.
var (
	// ErrEndpointExists is an import whose id the tenant already has.
	ErrEndpointExists = statusError{status: http.StatusConflict, text: "webhook: an endpoint with this id already exists"}
	// ErrDeliveryInProgress is a redelivery of a delivery whose attempt is
	// in progress.
	ErrDeliveryInProgress = statusError{status: http.StatusConflict, text: "webhook: the delivery is being attempted right now"}
	// ErrNotRedeliverable is a delivery that has no stored endpoint to be
	// sent to again: one made by Outgoing.
	ErrNotRedeliverable = statusError{status: http.StatusConflict, text: "webhook: the delivery was not made to a stored endpoint"}
)

// endpointInput is a request that passed validation.
type endpointInput struct {
	EndpointRequest
	url     string
	events  []string
	headers map[string]string
	policy  *Policy
}

// EndpointService is the use cases of the sending side: the endpoints, their
// secrets, the test call, the deliveries and their attempts. It owns the
// database handle; every exported method asks the policy before it reads or
// writes, and every act that changes something, or reveals a secret, stores
// its event in the application's outbox in the same transaction.
type EndpointService struct {
	db     *data.DB
	policy EndpointPolicy
	sender *sender
	audit  *auditor
}

func newEndpointService(db *data.DB, s *sender) *EndpointService {
	return &EndpointService{db: db, sender: s, audit: s.audit}
}

func (s *EndpointService) validate(in EndpointRequest) (endpointInput, validation.Errors) {
	e := validation.Errors{}
	out := endpointInput{EndpointRequest: in, headers: map[string]string{}}
	out.Name = strings.TrimSpace(in.Name)
	validation.Required(e, "name", out.Name)
	validation.MaxLen(e, "name", out.Name, 120)
	if in.Policy != nil {
		if err := in.Policy.Validate(); err != nil {
			e.Add("policy", "The delivery policy cannot be used: "+err.Error()+".")
		} else {
			policy := in.Policy.clone()
			out.policy = &policy
		}
	}
	url, err := hwebhook.NormalizeURL(in.URL)
	if err != nil {
		e.Add("url", "Enter a complete http:// or https:// address, without a user or password.")
	}
	out.url = url
	seen := map[string]bool{}
	for _, name := range in.Events {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		if name != AllEvents && s.sender.allowed != nil && !s.sender.allowed[name] {
			e.Add("events", "Choose events from the list.")
			break
		}
		seen[name] = true
		out.events = append(out.events, name)
	}
	if len(out.events) == 0 && !s.sender.allowEmpty {
		e.Add("events", "Choose at least one event.")
	}
	dialect := strings.TrimSpace(in.Dialect)
	if dialect == "" {
		dialect = strings.TrimSpace(in.Signer)
	}
	switch dialect {
	case "", DialectArandu:
		out.Dialect, out.SignatureHeader = DialectArandu, ""
	case DialectStandardWebhooks:
		out.Dialect, out.SignatureHeader = DialectStandardWebhooks, ""
	case DialectHMAC:
		out.Dialect = DialectHMAC
		out.SignatureHeader = strings.TrimSpace(in.SignatureHeader)
		if out.SignatureHeader == "" {
			out.SignatureHeader = DefaultSignatureHeader
		}
		if !headerPattern.MatchString(out.SignatureHeader) || s.sender.reserved(out.SignatureHeader) {
			e.Add("signature_header", "Name a header such as Signature or X-Signature-256.")
		}
	default:
		e.Add("dialect", "Choose the Arandu signature, the HMAC of the body or Standard Webhooks.")
	}
	for _, line := range strings.Split(in.Headers, "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || !headerPattern.MatchString(name) || s.sender.reserved(name) || strings.EqualFold(name, out.SignatureHeader) {
			e.Add("headers", "Write one \"Name: value\" per line; Content-Type, User-Agent and the signature headers belong to the delivery.")
			break
		}
		out.headers[http.CanonicalHeaderKey(name)] = value
	}
	if len(out.headers) > MaxHeaders {
		e.Add("headers", "Use at most 20 headers.")
	}
	return out, e
}

// checkAddress refuses an http address under a policy that is HTTPSOnly.
func checkAddress(e validation.Errors, url string, policy Policy) {
	if url != "" && policy.HTTPSOnly && !strings.HasPrefix(url, "https://") {
		e.Add("url", "Enter an https:// address.")
	}
}

// checkSecret refuses a secret the dialect cannot sign with.
func checkSecret(e validation.Errors, field, dialect, secret string) {
	if dialect == DialectStandardWebhooks {
		if _, err := standardKey(secret); err != nil {
			e.Add(field, "Use whsec_ and the standard base64 of a 24 to 64 byte key.")
		}
		return
	}
	if len(secret) < MinSecretBytes {
		e.Add(field, "Use a secret of at least 32 bytes.")
	}
}

// List returns a page of the tenant's endpoints, by name.
func (s *EndpointService) List(ctx context.Context, actor security.Subject, q data.Query) ([]*Endpoint, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointList, Endpoint{})
	if err != nil {
		return nil, err
	}
	query := Endpoints(s.db)
	if q.Cursor != "" {
		anchor, err := Endpoints(s.db).WhereKey(q.Cursor).Value(ctx, g, "name")
		if err != nil {
			return nil, err
		}
		if anchor == nil {
			return nil, nil
		}
		query = query.Where(func(after *EndpointQuery) {
			after.Where("name", ">", anchor).OrWhere(func(equal *EndpointQuery) {
				equal.Where("name", "=", anchor).Where("id", ">", q.Cursor)
			})
		})
	}
	return query.OrderBy("name").OrderBy("id").Limit(limitOf(q.Limit)).Get(ctx, g)
}

// Find returns one endpoint, and asks the policy about it once it is read.
func (s *EndpointService) Find(ctx context.Context, actor security.Subject, id string) (*Endpoint, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointView, Endpoint{})
	if err != nil {
		return nil, err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return nil, err
	}
	return s.authorized(ctx, actor, EndpointView, record)
}

// authorized asks the policy about a record that was read, and answers a
// missing one and a refused one alike.
func (s *EndpointService) authorized(ctx context.Context, actor security.Subject, a security.Action, record *Endpoint) (*Endpoint, error) {
	if record == nil {
		return nil, ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, a, *record); err != nil {
		return nil, ErrNotFound
	}
	return record, nil
}

// Create adds an endpoint with a new signing secret, answered in clear this
// once for the person to give the receiver.
func (s *EndpointService) Create(ctx context.Context, actor security.Subject, in EndpointRequest) (*Endpoint, string, error) {
	valid, errs := s.validate(in)
	checkAddress(errs, valid.url, s.effective(valid.policy, nil))
	if errs.Any() {
		return nil, "", errs
	}
	g, err := security.Authorize(ctx, s.policy, actor, EndpointCreate, Endpoint{})
	if err != nil {
		return nil, "", err
	}
	record, err := Endpoints(s.db).New()
	if err != nil {
		return nil, "", err
	}
	if record.ID, err = data.NewID(); err != nil {
		return nil, "", err
	}
	record.TenantID = data.Tenant(g)
	secret, err := newSecret()
	if err != nil {
		return nil, "", err
	}
	if record.Secret, err = s.sender.sealer.seal(record.TenantID, record.ID, "secret", secret); err != nil {
		return nil, "", err
	}
	if err := s.apply(record, valid, false); err != nil {
		return nil, "", err
	}
	record.CreatedAt = record.UpdatedAt
	err = data.Transaction(ctx, s.db, func(ctx context.Context) error {
		if _, err := record.Save(ctx, g); err != nil {
			return err
		}
		return s.audit.record(ctx, g, EventEndpointCreated, aggregateEndpoint, record.ID, endpointFacts(record))
	})
	if err != nil {
		return nil, "", err
	}
	return record, secret, nil
}

// effective is the policy an endpoint is held to: the one asked for, the one
// it has, or the server's.
func (s *EndpointService) effective(asked *Policy, record *Endpoint) Policy {
	if asked != nil {
		return asked.clone()
	}
	return s.sender.policyOf(record)
}

// Update changes an endpoint. The secret stays, and empty headers keep the
// stored ones. Turning it on here is turning it on with Enable: the count
// of failures is cleared, and the deliveries it kept waiting go. A change to DialectStandardWebhooks needs a secret that
// dialect can sign with: rotate first when the endpoint's is not one.
func (s *EndpointService) Update(ctx context.Context, actor security.Subject, id string, in EndpointRequest) (*Endpoint, error) {
	valid, errs := s.validate(in)
	if errs.Any() {
		return nil, errs
	}
	g, err := security.Authorize(ctx, s.policy, actor, EndpointUpdate, Endpoint{})
	if err != nil {
		return nil, err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if record, err = s.authorized(ctx, actor, EndpointUpdate, record); err != nil {
		return nil, err
	}
	if in.ResetPolicy {
		record.Policy = ""
	}
	checkAddress(errs, valid.url, s.effective(valid.policy, record))
	if valid.Dialect == DialectStandardWebhooks && record.Dialect != DialectStandardWebhooks {
		secret, err := s.sender.sealer.open(record.TenantID, record.ID, "secret", record.Secret)
		if err != nil {
			return nil, err
		}
		checkSecret(errs, "dialect", DialectStandardWebhooks, secret)
	}
	if errs.Any() {
		return nil, errs
	}
	before, was := endpointFacts(record), bool(record.Active)
	if err := s.apply(record, valid, strings.TrimSpace(in.Headers) == ""); err != nil {
		return nil, err
	}
	turnedOn := !was && bool(record.Active)
	if turnedOn {
		record.Enable(s.sender.clock())
	}
	err = data.Transaction(ctx, s.db, func(ctx context.Context) error {
		if _, err := record.Save(ctx, g); err != nil {
			return err
		}
		if turnedOn {
			if err := s.sender.resume(ctx, g, record); err != nil {
				return err
			}
		}
		return s.audit.record(ctx, g, EventEndpointUpdated, aggregateEndpoint, record.ID, map[string]any{
			"before": before, "after": endpointFacts(record),
		})
	})
	return record, err
}

// Delete removes an endpoint. Its deliveries still waiting fail as
// FailureEndpointDeleted at their next attempt: there is nothing left to sign
// them with.
func (s *EndpointService) Delete(ctx context.Context, actor security.Subject, id string) error {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointDelete, Endpoint{})
	if err != nil {
		return err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return err
	}
	if record, err = s.authorized(ctx, actor, EndpointDelete, record); err != nil {
		return err
	}
	return data.Transaction(ctx, s.db, func(ctx context.Context) error {
		if _, err := record.Delete(ctx, g); err != nil {
			return err
		}
		return s.audit.record(ctx, g, EventEndpointDeleted, aggregateEndpoint, record.ID, endpointFacts(record))
	})
}

// Enable turns an endpoint on, clears what the engine recorded when it
// turned it off, and queues again the deliveries it kept waiting.
func (s *EndpointService) Enable(ctx context.Context, actor security.Subject, id string) (*Endpoint, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointUpdate, Endpoint{})
	if err != nil {
		return nil, err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if record, err = s.authorized(ctx, actor, EndpointUpdate, record); err != nil {
		return nil, err
	}
	return record, s.toggle(ctx, g, record, true, "")
}

// Disable turns an endpoint off. Its deliveries wait until it is turned on;
// a redelivery or a test still goes.
func (s *EndpointService) Disable(ctx context.Context, actor security.Subject, id string) (*Endpoint, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointUpdate, Endpoint{})
	if err != nil {
		return nil, err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if record, err = s.authorized(ctx, actor, EndpointUpdate, record); err != nil {
		return nil, err
	}
	return record, s.toggle(ctx, g, record, false, "")
}

// DisableWithReason turns an endpoint off as Disable does, and keeps why:
// the reason is the endpoint's DisabledReason, with DisabledAt, and is in the
// event that records it. It is one line of printable text of at most
// MaxDisabledReason bytes.
func (s *EndpointService) DisableWithReason(ctx context.Context, actor security.Subject, id, reason string) (*Endpoint, error) {
	if !validReason(reason) || reason == "" {
		errs := validation.Errors{}
		errs.Add("reason", "Say why in one line of at most 64 characters.")
		return nil, errs
	}
	g, err := security.Authorize(ctx, s.policy, actor, EndpointUpdate, Endpoint{})
	if err != nil {
		return nil, err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if record, err = s.authorized(ctx, actor, EndpointUpdate, record); err != nil {
		return nil, err
	}
	return record, s.toggle(ctx, g, record, false, reason)
}

// toggle turns an authorized endpoint on or off and records it.
func (s *EndpointService) toggle(ctx context.Context, g security.Grant, record *Endpoint, on bool, reason string) error {
	was := bool(record.Active)
	event := EventEndpointDisabled
	payload := map[string]any{"was_active": was}
	if on {
		record.Enable(s.sender.clock())
		event = EventEndpointEnabled
	} else {
		record.Disable(reason, s.sender.clock())
		if reason != "" {
			payload["reason"] = reason
		}
	}
	return data.Transaction(ctx, s.db, func(ctx context.Context) error {
		if _, err := record.Save(ctx, g); err != nil {
			return err
		}
		if on && !was {
			if err := s.sender.resume(ctx, g, record); err != nil {
				return err
			}
		}
		return s.audit.record(ctx, g, event, aggregateEndpoint, record.ID, payload)
	})
}

// Secret returns an endpoint's signing secret, for the panel's copy button.
func (s *EndpointService) Secret(ctx context.Context, actor security.Subject, id string) (string, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointSecret, Endpoint{})
	if err != nil {
		return "", err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return "", err
	}
	if record, err = s.authorized(ctx, actor, EndpointSecret, record); err != nil {
		return "", err
	}
	secret, err := s.sender.sealer.open(record.TenantID, record.ID, "secret", record.Secret)
	if err != nil {
		return "", err
	}
	err = data.Transaction(ctx, s.db, func(ctx context.Context) error {
		return s.audit.record(ctx, g, EventSecretRevealed, aggregateEndpoint, record.ID, map[string]any{})
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// Rotate gives an endpoint a new signing secret, answered in clear this
// once. The secret it had keeps signing beside the new one for overlap -- a
// Standard Webhooks call then carries both signatures -- and one still
// retiring from an earlier rotation is revoked. An overlap of zero or less
// revokes the old secret at once.
func (s *EndpointService) Rotate(ctx context.Context, actor security.Subject, id string, overlap time.Duration) (string, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointRotate, Endpoint{})
	if err != nil {
		return "", err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return "", err
	}
	if record, err = s.authorized(ctx, actor, EndpointRotate, record); err != nil {
		return "", err
	}
	old, err := s.sender.sealer.open(record.TenantID, record.ID, "secret", record.Secret)
	if err != nil {
		return "", err
	}
	secret, err := newSecret()
	if err != nil {
		return "", err
	}
	now := s.sender.clock()
	var previous []PreviousSecret
	payload := map[string]any{"overlap_seconds": int64(0)}
	if overlap > 0 {
		retires := now.Add(overlap)
		previous = []PreviousSecret{{Secret: old, RetiresAt: retires}}
		payload = map[string]any{"overlap_seconds": int64(overlap / time.Second), "retires_at": retires.Format(time.RFC3339)}
	}
	if record.Secret, err = s.sender.sealer.seal(record.TenantID, record.ID, "secret", secret); err != nil {
		return "", err
	}
	if record.PreviousSecrets, err = s.sender.sealer.sealPrevious(record.TenantID, record.ID, previous); err != nil {
		return "", err
	}
	record.UpdatedAt = now
	err = data.Transaction(ctx, s.db, func(ctx context.Context) error {
		if _, err := record.Save(ctx, g); err != nil {
			return err
		}
		return s.audit.record(ctx, g, EventSecretRotated, aggregateEndpoint, record.ID, payload)
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// Import stores an endpoint an application kept elsewhere, keeping its id
// and its secrets, sealed with this module's key and bound to the tenant and
// the id. It is the data migration's: EndpointImport is not among Actions.
func (s *EndpointService) Import(ctx context.Context, actor security.Subject, in ImportRequest) (*Endpoint, error) {
	valid, errs := s.validate(in.EndpointRequest)
	if !validID(in.ID, maxIdentifierLen) {
		errs.Add("id", "Use up to 64 letters, digits, '_', '.', ':' and '-'.")
	}
	checkAddress(errs, valid.url, s.effective(valid.policy, nil))
	checkSecret(errs, "secret", valid.Dialect, in.Secret)
	for _, p := range in.PreviousSecrets {
		checkSecret(errs, "previous_secrets", valid.Dialect, p.Secret)
	}
	if len(in.PreviousSecrets) > MaxPreviousSecrets {
		errs.Add("previous_secrets", "Keep at most 5 previous secrets.")
	}
	if in.ConsecutiveFailures < 0 {
		errs.Add("consecutive_failures", "A count of failures cannot be negative.")
	}
	switch {
	case !validReason(in.DisabledReason):
		errs.Add("disabled_reason", "Say why in one line of at most 64 characters.")
	case (in.DisabledAt == nil) != (in.DisabledReason == ""):
		errs.Add("disabled_reason", "Give when and why it was turned off together, or neither.")
	case in.DisabledAt != nil && in.Active:
		errs.Add("disabled_reason", "An endpoint turned off is not active.")
	}
	if errs.Any() {
		return nil, errs
	}
	g, err := security.Authorize(ctx, s.policy, actor, EndpointImport, Endpoint{})
	if err != nil {
		return nil, err
	}
	existing, err := Endpoints(s.db).WhereKey(in.ID).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrEndpointExists
	}
	record, err := Endpoints(s.db).New()
	if err != nil {
		return nil, err
	}
	record.ID = in.ID
	record.TenantID = data.Tenant(g)
	now := s.sender.clock()
	if record.Secret, err = s.sender.sealer.seal(record.TenantID, record.ID, "secret", in.Secret); err != nil {
		return nil, err
	}
	if record.PreviousSecrets, err = s.sender.sealer.sealPrevious(record.TenantID, record.ID, stillSigning(in.PreviousSecrets, now)); err != nil {
		return nil, err
	}
	if err := s.apply(record, valid, false); err != nil {
		return nil, err
	}
	record.CreatedAt = now
	record.ConsecutiveFailures = in.ConsecutiveFailures
	if in.DisabledAt != nil {
		at := in.DisabledAt.UTC()
		record.DisabledAt, record.DisabledReason = &at, in.DisabledReason
	}
	created := now
	if !in.CreatedAt.IsZero() {
		created = in.CreatedAt.UTC()
	}
	err = data.Transaction(ctx, s.db, func(ctx context.Context) error {
		if _, err := record.Save(ctx, g); err != nil {
			return err
		}
		// The Model stamps created_at with the moment of the insert; the
		// moment the endpoint was created where it comes from is written
		// over it.
		if _, err := Endpoints(s.db).WhereKey(record.ID).Update(ctx, g, map[string]any{"created_at": created}); err != nil {
			return err
		}
		record.CreatedAt = created
		facts := endpointFacts(record)
		facts["created_at"] = created.Format(time.RFC3339)
		return s.audit.record(ctx, g, EventEndpointImported, aggregateEndpoint, record.ID, facts)
	})
	if err != nil {
		return nil, err
	}
	return record, nil
}

// HeaderNames returns the names of an endpoint's extra headers, for its form.
// The values are never shown back.
func (s *EndpointService) HeaderNames(ctx context.Context, actor security.Subject, id string) ([]string, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointUpdate, Endpoint{})
	if err != nil {
		return nil, err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if record, err = s.authorized(ctx, actor, EndpointUpdate, record); err != nil {
		return nil, err
	}
	names := []string{}
	if record.Headers == "" {
		return names, nil
	}
	plain, err := s.sender.sealer.open(record.TenantID, record.ID, "headers", record.Headers)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	if err := json.Unmarshal([]byte(plain), &headers); err != nil {
		return nil, err
	}
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// Test queues one webhook.test call to an endpoint, whatever it subscribes
// to and whether or not it is active, and answers its delivery.
func (s *EndpointService) Test(ctx context.Context, actor security.Subject, id string) (*Delivery, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointTest, Endpoint{})
	if err != nil {
		return nil, err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if record, err = s.authorized(ctx, actor, EndpointTest, record); err != nil {
		return nil, err
	}
	item, err := s.sender.target(record)
	if err != nil {
		return nil, err
	}
	if item.id, err = newDeliveryID(record.Dialect); err != nil {
		return nil, err
	}
	now := s.sender.clock().Format(time.RFC3339)
	body := map[string]any{"event": TestEvent, "id": item.id, "sent_at": now}
	if record.Dialect == DialectStandardWebhooks {
		body = map[string]any{"id": item.id, "type": TestEvent, "timestamp": now, "data": map[string]any{}}
	}
	item.event, item.trigger = TestEvent, AttemptManual
	item.body, _ = json.Marshal(body)
	var delivery *Delivery
	err = data.Transaction(ctx, s.db, func(ctx context.Context) error {
		//arandu:system-grant the endpoint policy authorized this test above, in the endpoint's tenant; the delivery is recorded under the module's dispatch action.
		rows, err := s.sender.record(ctx, security.SystemGrant(DeliveryDispatch, data.Tenant(g)), []outgoing{item})
		if err != nil {
			return err
		}
		delivery = rows[0]
		return s.audit.record(ctx, g, EventEndpointTested, aggregateEndpoint, record.ID, map[string]any{"delivery_id": delivery.ID})
	})
	if err != nil {
		return nil, err
	}
	return delivery, nil
}

// Deliveries returns an endpoint's latest deliveries, newest first: what
// webhook-server tells through its WebhookCallSucceeded and
// WebhookCallFailed events, read from the record each attempt leaves.
func (s *EndpointService) Deliveries(ctx context.Context, actor security.Subject, id string, limit int) ([]*Delivery, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointView, Endpoint{})
	if err != nil {
		return nil, err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if record, err = s.authorized(ctx, actor, EndpointView, record); err != nil {
		return nil, err
	}
	return Deliveries(s.db).Where("endpoint_id", "=", record.ID).OrderByDesc("created_at").OrderByDesc("id").Limit(limitOf(limit)).Get(ctx, g)
}

// delivery reads one delivery of a stored endpoint and asks the policy about
// the endpoint for the action.
func (s *EndpointService) delivery(ctx context.Context, g security.Grant, actor security.Subject, a security.Action, row *Delivery) (*Delivery, *Endpoint, error) {
	if row == nil {
		return nil, nil, ErrNotFound
	}
	record, err := Endpoints(s.db).WhereKey(row.EndpointID).First(ctx, g)
	if err != nil {
		return nil, nil, err
	}
	if record == nil {
		if strings.HasPrefix(row.SecretRef, endpointSecretRef) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, ErrNotRedeliverable
	}
	if record, err = s.authorized(ctx, actor, a, record); err != nil {
		return nil, nil, err
	}
	return row, record, nil
}

// Delivery returns one delivery of the tenant's endpoints.
func (s *EndpointService) Delivery(ctx context.Context, actor security.Subject, deliveryID string) (*Delivery, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointView, Endpoint{})
	if err != nil {
		return nil, err
	}
	row, err := Deliveries(s.db).WhereKey(deliveryID).First(ctx, g)
	if err != nil {
		return nil, err
	}
	row, _, err = s.delivery(ctx, g, actor, EndpointView, row)
	return row, err
}

// Attempts returns a delivery's attempts, first first: n of MaxAttempts, what
// the receiver answered, when, and how long it took.
func (s *EndpointService) Attempts(ctx context.Context, actor security.Subject, deliveryID string) ([]*DeliveryAttempt, error) {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointView, Endpoint{})
	if err != nil {
		return nil, err
	}
	row, err := Deliveries(s.db).WhereKey(deliveryID).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if row, _, err = s.delivery(ctx, g, actor, EndpointView, row); err != nil {
		return nil, err
	}
	return DeliveryAttempts(s.db).Where("delivery_id", "=", row.ID).OrderBy("attempt").OrderBy("created_at").Limit(maxLimit).Get(ctx, g)
}

// Redeliver sends a delivery again, now: the same id and the same body, under
// a new timestamp and signature, whether it was delivered, gave up or is
// waiting. A delivery that had no attempt left is given one more.
func (s *EndpointService) Redeliver(ctx context.Context, actor security.Subject, deliveryID string) (*Delivery, error) {
	g, err := security.Authorize(ctx, s.policy, actor, DeliveryRedeliver, Endpoint{})
	if err != nil {
		return nil, err
	}
	row, err := Deliveries(s.db).WhereKey(deliveryID).First(ctx, g)
	if err != nil {
		return nil, err
	}
	row, endpoint, err := s.delivery(ctx, g, actor, DeliveryRedeliver, row)
	if err != nil {
		return nil, err
	}
	now := s.sender.clock()
	if row.Status == DeliveryProcessing && row.LeaseUntil != nil && row.LeaseUntil.After(now) {
		return nil, ErrDeliveryInProgress
	}
	tries := row.MaxAttempts
	if row.Attempts >= tries {
		tries = row.Attempts + 1
	}
	policy := s.sender.policyOf(endpoint)
	err = data.Transaction(ctx, s.db, func(ctx context.Context) error {
		moved, err := Deliveries(s.db).WhereKey(row.ID).Where("attempts", "=", row.Attempts).Where("status", "=", row.Status).Update(ctx, g, map[string]any{
			"status": DeliveryPending, "next_attempt_at": now, "max_attempts": tries, "permanent": Flag(false),
			"claim_token": nil, "lease_until": nil,
		})
		if err != nil {
			return err
		}
		if moved == 0 {
			return ErrDeliveryInProgress
		}
		if err := s.sender.schedule(ctx, data.Tenant(g), row.ID, row.Attempts, AttemptManual, now, policy.Timeout); err != nil {
			return err
		}
		return s.audit.record(ctx, g, EventDeliveryRedelivered, aggregateDelivery, row.ID, map[string]any{
			"endpoint_id": endpoint.ID, "attempts": row.Attempts,
		})
	})
	if err != nil {
		return nil, err
	}
	return Deliveries(s.db).WhereKey(row.ID).First(ctx, g)
}

func (s *EndpointService) apply(record *Endpoint, in endpointInput, keepHeaders bool) error {
	record.Name, record.URL, record.Active = in.Name, in.url, Flag(in.Active)
	record.Events = strings.Join(in.events, ",")
	record.Dialect, record.Signer, record.SignatureHeader = in.Dialect, signerFor(in.Dialect), in.SignatureHeader
	record.AranduHeaders = Flag(!in.WithoutAranduHeaders)
	record.UpdatedAt = s.sender.clock()
	if in.policy != nil {
		encoded, err := encodePolicy(in.policy)
		if err != nil {
			return err
		}
		record.Policy = encoded
	}
	if keepHeaders {
		return nil
	}
	record.Headers = ""
	if len(in.headers) == 0 {
		return nil
	}
	encoded, err := json.Marshal(in.headers)
	if err != nil {
		return err
	}
	record.Headers, err = s.sender.sealer.seal(record.TenantID, record.ID, "headers", string(encoded))
	return err
}

// CallService is the use cases of the receiving side's record: reading the
// calls, processing one again, and the clean. It owns the database handle;
// every exported method asks the policy before it reads or writes.
type CallService struct {
	db     *data.DB
	policy CallPolicy
	client *client
}

func newCallService(db *data.DB, c *client) *CallService { return &CallService{db: db, client: c} }

// CallFilter narrows a listing of calls.
type CallFilter struct {
	// Name is a receiver's name.
	Name string
	// Status is one of the CallStatus values.
	Status CallStatus
}

// List returns a page of the tenant's received calls, newest first.
func (s *CallService) List(ctx context.Context, actor security.Subject, filter CallFilter, q data.Query) ([]*Call, error) {
	g, err := security.Authorize(ctx, s.policy, actor, CallList, Call{})
	if err != nil {
		return nil, err
	}
	query := Calls(s.db)
	if filter.Name != "" {
		query = query.Where("name", "=", filter.Name)
	}
	if filter.Status != "" {
		query = query.Where("status", "=", string(filter.Status))
	}
	if q.Cursor != "" {
		anchor, err := Calls(s.db).WhereKey(q.Cursor).Value(ctx, g, "created_at")
		if err != nil {
			return nil, err
		}
		if anchor == nil {
			return nil, nil
		}
		query = query.Where(func(before *CallQuery) {
			before.Where("created_at", "<", anchor).OrWhere(func(equal *CallQuery) {
				equal.Where("created_at", "=", anchor).Where("id", "<", q.Cursor)
			})
		})
	}
	return query.OrderByDesc("created_at").OrderByDesc("id").Limit(limitOf(q.Limit)).Get(ctx, g)
}

// Find returns one received call.
func (s *CallService) Find(ctx context.Context, actor security.Subject, id string) (*Call, error) {
	g, err := security.Authorize(ctx, s.policy, actor, CallView, Call{})
	if err != nil {
		return nil, err
	}
	record, err := Calls(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, CallView, *record); err != nil {
		return nil, ErrNotFound
	}
	return record, nil
}

// ErrNoReceiver is a call whose receiver the configuration no longer has.
var ErrNoReceiver = errors.New("webhook: the call's receiver is not configured any more")

// Process queues a stored call for its receiver's Processor again, whatever
// its status: the call that failed after a fix, or the one to run twice on
// purpose.
func (s *CallService) Process(ctx context.Context, actor security.Subject, id string) error {
	g, err := security.Authorize(ctx, s.policy, actor, CallProcess, Call{})
	if err != nil {
		return err
	}
	record, err := Calls(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return err
	}
	if record == nil {
		return ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, CallProcess, *record); err != nil {
		return ErrNotFound
	}
	rc, ok := s.client.receivers[record.Name]
	if !ok {
		return ErrNoReceiver
	}
	return data.Transaction(ctx, s.db, func(ctx context.Context) error {
		if err := s.client.enqueue(ctx, rc, record); err != nil {
			return err
		}
		return s.client.audit.record(ctx, g, EventCallReprocessed, aggregateCall, record.ID, map[string]any{
			"receiver": record.Name, "status": string(record.Status), "attempts": record.Attempts,
		})
	})
}

// clean removes the calls older than the cutoff, in the Grant's tenant.
func (s *CallService) clean(ctx context.Context, g security.Grant, cutoff time.Time) (int64, error) {
	if err := g.Check(CallClean); err != nil {
		return 0, err
	}
	return Calls(s.db).Where("created_at", "<", cutoff).Delete(ctx, g)
}

func limitOf(limit int) int {
	switch {
	case limit <= 0:
		return defaultLimit
	case limit > maxLimit:
		return maxLimit
	}
	return limit
}

// newSecret is a signing secret: whsec_ and the standard base64 of 32
// random bytes, which every dialect signs with -- Standard Webhooks with the
// key it encodes, the others with the text itself.
func newSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return StandardSecretPrefix + base64.StdEncoding.EncodeToString(raw), nil
}
