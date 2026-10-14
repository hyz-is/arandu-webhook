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

// EndpointRequest is an endpoint as a form or a client sends it.
//
// There is no TenantID here and there must never be one: the tenant comes
// from the Grant, which comes from the session.
type EndpointRequest struct {
	Name string
	URL  string
	// Events are the event names it receives; AllEvents receives every one.
	Events []string
	// Signer is SignerArandu (empty means it) or SignerHMAC.
	Signer string
	// SignatureHeader is where a SignerHMAC signature goes. Empty means
	// DefaultSignatureHeader.
	SignatureHeader string
	// Headers is "Name: value" per line. On an update, empty keeps the stored
	// headers, which are never shown back.
	Headers string
	Active  bool
}

// endpointInput is a request that passed validation.
type endpointInput struct {
	EndpointRequest
	url     string
	events  []string
	headers map[string]string
}

// EndpointService is the use cases of the sending side: the endpoints, their
// secrets, the test call and the record of deliveries. It owns the database
// handle; every exported method asks the policy before it reads or writes.
type EndpointService struct {
	db     *data.DB
	policy EndpointPolicy
	sender *sender
	now    func() time.Time
}

func newEndpointService(db *data.DB, s *sender) *EndpointService {
	return &EndpointService{db: db, sender: s, now: func() time.Time { return time.Now().UTC() }}
}

func (s *EndpointService) validate(in EndpointRequest) (endpointInput, validation.Errors) {
	e := validation.Errors{}
	out := endpointInput{EndpointRequest: in, headers: map[string]string{}}
	out.Name = strings.TrimSpace(in.Name)
	validation.Required(e, "name", out.Name)
	validation.MaxLen(e, "name", out.Name, 120)
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
	if len(out.events) == 0 {
		e.Add("events", "Choose at least one event.")
	}
	switch strings.TrimSpace(in.Signer) {
	case "", SignerArandu:
		out.Signer, out.SignatureHeader = SignerArandu, ""
	case SignerHMAC:
		out.Signer = SignerHMAC
		out.SignatureHeader = strings.TrimSpace(in.SignatureHeader)
		if out.SignatureHeader == "" {
			out.SignatureHeader = DefaultSignatureHeader
		}
		if !headerPattern.MatchString(out.SignatureHeader) || s.sender.reserved(out.SignatureHeader) {
			e.Add("signature_header", "Name a header such as Signature or X-Signature-256.")
		}
	default:
		e.Add("signer", "Choose the Arandu signature or the HMAC of the body.")
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
	if record == nil {
		return nil, ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, EndpointView, *record); err != nil {
		return nil, ErrNotFound
	}
	return record, nil
}

// Create adds an endpoint with a new signing secret, answered in clear this
// once for the person to give the receiver.
func (s *EndpointService) Create(ctx context.Context, actor security.Subject, in EndpointRequest) (*Endpoint, string, error) {
	valid, errs := s.validate(in)
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
	if _, err := record.Save(ctx, g); err != nil {
		return nil, "", err
	}
	return record, secret, nil
}

// Update changes an endpoint. The secret stays, and empty headers keep the
// stored ones.
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
	if record == nil {
		return nil, ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, EndpointUpdate, *record); err != nil {
		return nil, ErrNotFound
	}
	if err := s.apply(record, valid, strings.TrimSpace(in.Headers) == ""); err != nil {
		return nil, err
	}
	_, err = record.Save(ctx, g)
	return record, err
}

// Delete removes an endpoint. Deliveries already queued still go out.
func (s *EndpointService) Delete(ctx context.Context, actor security.Subject, id string) error {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointDelete, Endpoint{})
	if err != nil {
		return err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return err
	}
	if record == nil {
		return ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, EndpointDelete, *record); err != nil {
		return ErrNotFound
	}
	_, err = record.Delete(ctx, g)
	return err
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
	if record == nil {
		return "", ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, EndpointSecret, *record); err != nil {
		return "", ErrNotFound
	}
	return s.sender.sealer.open(record.TenantID, record.ID, "secret", record.Secret)
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
	if record == nil {
		return nil, ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, EndpointUpdate, *record); err != nil {
		return nil, ErrNotFound
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
// to and whether or not it is active.
func (s *EndpointService) Test(ctx context.Context, actor security.Subject, id string) error {
	g, err := security.Authorize(ctx, s.policy, actor, EndpointTest, Endpoint{})
	if err != nil {
		return err
	}
	record, err := Endpoints(s.db).WhereKey(id).First(ctx, g)
	if err != nil {
		return err
	}
	if record == nil {
		return ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, EndpointTest, *record); err != nil {
		return ErrNotFound
	}
	eventID, err := data.NewID()
	if err != nil {
		return err
	}
	now := s.now()
	body, _ := json.Marshal(map[string]any{"event": TestEvent, "id": eventID, "sent_at": now.Format(time.RFC3339)})
	//arandu:system-grant the endpoint policy authorized this test above, in the endpoint's tenant; the delivery runs under hesape's own dispatch action.
	dispatch := security.SystemGrant(hwebhook.ActionDispatch, data.Tenant(g))
	return s.sender.manager.Dispatch(ctx, dispatch, hwebhook.Event{
		ID: eventID, Name: TestEvent, Aggregate: "webhook_endpoint", AggregateID: record.ID, Payload: body, OccurredAt: now,
	}, []hwebhook.Endpoint{s.sender.target(record, body)})
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
	if record == nil {
		return nil, ErrNotFound
	}
	if _, err := security.Authorize(ctx, s.policy, actor, EndpointView, *record); err != nil {
		return nil, ErrNotFound
	}
	return Deliveries(s.db).Where("endpoint_id", "=", record.ID).OrderByDesc("created_at").OrderByDesc("id").Limit(limitOf(limit)).Get(ctx, g)
}

func (s *EndpointService) apply(record *Endpoint, in endpointInput, keepHeaders bool) error {
	record.Name, record.URL, record.Active = in.Name, in.url, Flag(in.Active)
	record.Events = strings.Join(in.events, ",")
	record.Signer, record.SignatureHeader = in.Signer, in.SignatureHeader
	record.UpdatedAt = s.now()
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
	return s.client.enqueue(ctx, rc, record)
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

// newSecret is a signing secret: whsec_ and 32 random bytes.
func newSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "whsec_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
