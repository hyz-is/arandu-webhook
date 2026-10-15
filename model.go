package webhook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/arandu-io/hesape/database/model"
)

// Endpoint is one destination the application sends to: an address, the
// events it subscribes to, how its calls are signed, and the extra headers
// they carry. The signing secret and the headers are sealed at rest.
//
// Endpoints, EndpointQuery and EndpointCollection are generated beside this
// file, in EndpointQuery.go, by aru model:build.
type Endpoint struct {
	model.Model

	ID       string `db:"id"`
	TenantID string `db:"tenant_id"`

	// Name is what a person calls the endpoint.
	Name string `db:"name"`
	// URL is the absolute http or https address the calls go to.
	URL string `db:"url"`
	// Events is the comma-separated list of event names it receives; "*"
	// receives every event.
	Events string `db:"events"`
	// Dialect is how its calls are signed and which headers they carry:
	// DialectArandu, DialectHMAC or DialectStandardWebhooks.
	Dialect string `db:"dialect"`
	// Signer is the column the previous release read the dialect from, kept in step with
	// Dialect for a binary of that release during a rollout: DialectArandu or
	// DialectHMAC, and DialectArandu for a dialect it does not know. Read
	// Dialect.
	Signer string `db:"signer"`
	// SignatureHeader is the header a DialectHMAC signature travels in.
	SignatureHeader string `db:"signature_header"`
	// AranduHeaders is whether a DialectHMAC call also carries the Arandu
	// signature, timestamp and delivery id headers. The other dialects ignore
	// it: an Arandu call always carries them, a Standard Webhooks call never.
	AranduHeaders Flag `db:"include_arandu_headers"`
	// Secret is the sealed signing secret. It never leaves in a response.
	Secret string `db:"secret"`
	// PreviousSecrets is the sealed JSON list of the secrets still signing
	// after a rotation, each until it retires; empty when none.
	PreviousSecrets string `db:"previous_secrets"`
	// Headers is the sealed JSON object of extra headers, empty when none.
	Headers string `db:"headers"`
	// Policy is the JSON of the endpoint's own delivery policy, empty when it
	// follows Server.Policy.
	Policy string `db:"policy"`
	// Active is whether it receives events.
	Active Flag `db:"active"`
	// ConsecutiveFailures is how many of its deliveries in a row gave up.
	ConsecutiveFailures int `db:"consecutive_failures"`
	// DisabledAt and DisabledReason say when and why it was turned off by the
	// engine; both are cleared when it is turned on.
	DisabledAt     *time.Time `db:"disabled_at"`
	DisabledReason string     `db:"disabled_reason"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// Call is one webhook another system sent to a receiver of this
// application: webhook-client's WebhookCall. The body is kept exactly as it
// arrived, because those are the bytes the signature was checked over.
//
// Calls, CallQuery and CallCollection are generated beside this file, in
// CallQuery.go, by aru model:build.
type Call struct {
	model.Model

	ID       string `db:"id"`
	TenantID string `db:"tenant_id"`

	// Name is the receiver it arrived at.
	Name string `db:"name"`
	// Reference is what the receiver's Resolve said the call is for -- the
	// record the processor finds again -- and empty for a static receiver.
	Reference string `db:"reference"`
	// Method and URL are how it arrived. URL is kept as the receiver's URL
	// mode says: whole, or only its route, so a bearer token in the path
	// is not kept.
	Method string `db:"method"`
	URL    string `db:"url"`
	// RemoteAddr is who connected, as the request reported it: the peer,
	// or what a proxy in front of the application wrote there.
	RemoteAddr string `db:"remote_addr"`
	// HeadersSHA256 is HeadersDigest of every header the call arrived with,
	// kept whatever StoreHeaders keeps: two senders told apart without
	// keeping what an unauthenticated sender put in a header.
	HeadersSHA256 string `db:"headers_sha256"`
	// HeaderData is the JSON object of the headers the receiver keeps, by
	// lowercase name.
	HeaderData string `db:"headers"`
	// Payload is the body, exactly as it arrived.
	Payload string `db:"payload"`
	// Status is where its processing stands.
	Status CallStatus `db:"status"`
	// Attempts is how many times it was processed.
	Attempts int `db:"attempts"`
	// Exception is the message of the last processing that failed, empty
	// when the last one did not.
	Exception string `db:"exception"`
	// ProcessedAt is when it was processed; it means something only when
	// Status is CallProcessed.
	ProcessedAt time.Time `db:"processed_at"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`

	// received is every header of the request, while the request is being
	// answered. It is not a column, and a pointer so Call stays comparable.
	received *http.Header
}

// CallStatus is where a received call stands.
type CallStatus string

const (
	// CallReceived is stored and waiting for the queue.
	CallReceived CallStatus = "received"
	// CallProcessed is handled.
	CallProcessed CallStatus = "processed"
	// CallFailed is the last processing having failed. The queue may still
	// retry it.
	CallFailed CallStatus = "failed"
)

// The dialects an endpoint is called in.
const (
	// DialectArandu signs with hesape's scheme: X-Arandu-Signature, sha256=
	// and the hex HMAC-SHA256 of the timestamp, the delivery id and the body,
	// beside X-Arandu-Timestamp and X-Arandu-Delivery-Id. Server.HeaderPrefix
	// renames the three.
	DialectArandu = "arandu"
	// DialectHMAC is webhook-server's DefaultSigner: the hex HMAC-SHA256 of
	// the body, in the endpoint's SignatureHeader, with the Arandu headers
	// beside it unless the endpoint turns them off.
	DialectHMAC = "hmac"
	// DialectStandardWebhooks is the Standard Webhooks specification:
	// Webhook-Id, Webhook-Timestamp and Webhook-Signature, which carries
	// "v1," and the base64 HMAC-SHA256 of id.timestamp.body under the key the
	// whsec_ secret encodes, once per secret still signing, newest first.
	DialectStandardWebhooks = "standard-webhooks"
)

// The signers of the previous release, which are the first two dialects.
const (
	// SignerArandu is DialectArandu.
	SignerArandu = DialectArandu
	// SignerHMAC is DialectHMAC.
	SignerHMAC = DialectHMAC
)

// Delivery is one message to one address, and where its attempts stand: the
// body frozen when it was recorded, the extra headers sealed beside it, the
// number of attempts it gets and the waits between them, and the receiver's
// last answer. The signature is made at each attempt, so neither a secret nor
// a signature is ever stored with it.
//
// Deliveries, DeliveryQuery and DeliveryCollection are generated beside this
// file, in DeliveryQuery.go, by aru model:build.
type Delivery struct {
	model.Model

	// ID is the delivery's identity: the Delivery-Id of the Arandu dialect
	// and the Webhook-Id of Standard Webhooks, the same on every attempt.
	ID       string `db:"id"`
	TenantID string `db:"tenant_id"`

	// EventID is what the delivery was made for; one event reaches one
	// endpoint once.
	EventID   string `db:"event_id"`
	EventName string `db:"event_name"`
	// EndpointID is the stored endpoint, or "url:" and a digest of the
	// address for a call built with Outgoing.
	EndpointID string `db:"endpoint_id"`
	URL        string `db:"url"`
	// Dialect is the endpoint's, when the delivery was recorded.
	Dialect string `db:"dialect"`
	// Body is the request body, exactly as every attempt sends it, and
	// BodySHA256 its hex SHA-256.
	Body       string `db:"body"`
	BodySHA256 string `db:"body_sha256"`
	// Headers is the sealed JSON object of extra headers, empty when none.
	Headers string `db:"headers"`
	// SecretRef names where the signing secrets are read from at each
	// attempt: the endpoint, or a secret of Server.Secrets.
	SecretRef string `db:"secret_ref"`
	// SignatureHeader and AranduHeaders are the DialectHMAC settings.
	SignatureHeader string `db:"signature_header"`
	AranduHeaders   Flag   `db:"include_arandu_headers"`
	// Status is pending, processing, delivered or failed.
	Status string `db:"status"`
	// Attempts is how many attempts were made, and MaxAttempts how many it
	// gets.
	Attempts    int64 `db:"attempts"`
	MaxAttempts int64 `db:"max_attempts"`
	// Backoff is the JSON list of the waits before each attempt after the
	// first, in milliseconds, frozen when the delivery was recorded.
	Backoff string `db:"backoff"`
	// Permanent is a failure retrying cannot fix.
	Permanent Flag `db:"permanent"`
	// NextAttemptAt is when the next attempt is due, while it is pending.
	NextAttemptAt  *time.Time `db:"next_attempt_at"`
	ResponseStatus *int64     `db:"response_status"`
	LastError      *string    `db:"last_error"`
	// ClaimToken and LeaseUntil are the attempt in progress: whoever holds the
	// token settles the attempt, and nobody else starts one until the lease
	// ends.
	ClaimToken  *string    `db:"claim_token"`
	LeaseUntil  *time.Time `db:"lease_until"`
	CreatedAt   time.Time  `db:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at"`
	DeliveredAt *time.Time `db:"delivered_at"`
}

// The states of a delivery.
const (
	// DeliveryPending waits for its next attempt.
	DeliveryPending = "pending"
	// DeliveryProcessing is an attempt in progress.
	DeliveryProcessing = "processing"
	// DeliveryDelivered was answered with a 2xx.
	DeliveryDelivered = "delivered"
	// DeliveryFailed gave up: its attempts are spent, or its last failure was
	// one retrying cannot fix.
	DeliveryFailed = "failed"
)

// DeliveryAttempt is one attempt of a delivery: when it was signed, what
// the receiver answered, how long it took. It is written when the attempt is
// settled, in the same transaction as the delivery.
//
// DeliveryAttempts, DeliveryAttemptQuery and DeliveryAttemptCollection are
// generated beside this file, in DeliveryAttemptQuery.go, by aru model:build.
type DeliveryAttempt struct {
	model.Model

	ID       string `db:"id"`
	TenantID string `db:"tenant_id"`

	DeliveryID string `db:"delivery_id"`
	EndpointID string `db:"endpoint_id"`
	// Attempt is its number, from 1.
	Attempt int64 `db:"attempt"`
	// Trigger is AttemptScheduled or AttemptManual.
	Trigger string `db:"triggered_by"`
	// Succeeded is whether the receiver answered with a 2xx.
	Succeeded Flag `db:"succeeded"`
	// ResponseStatus is the receiver's status, nil when there was no answer.
	ResponseStatus *int64 `db:"response_status"`
	// Error is the failure's code, empty when it succeeded.
	Error string `db:"error"`
	// Response is the start of the answer's body, as text, for the panel.
	Response string `db:"response"`
	// DurationMS is how long the request took.
	DurationMS int64 `db:"duration_ms"`
	// SignedAt is the timestamp the attempt was signed with.
	SignedAt  time.Time `db:"signed_at"`
	CreatedAt time.Time `db:"created_at"`
}

// What started an attempt.
const (
	// AttemptScheduled is an attempt the delivery's plan made.
	AttemptScheduled = "scheduled"
	// AttemptManual is an attempt somebody asked for: a redelivery.
	AttemptManual = "manual"
)

var deliveryTable = model.NewTable(model.TableSpec{
	Name:      deliveriesTable,
	New:       func() model.Entity { return new(Delivery) },
	ManualKey: true,
})

var deliveryAttemptTable = model.NewTable(model.TableSpec{
	Name:      attemptsTable,
	New:       func() model.Entity { return new(DeliveryAttempt) },
	ManualKey: true,
})

var endpointTable = model.NewTable(model.TableSpec{
	Name:      endpointsTable,
	New:       func() model.Entity { return new(Endpoint) },
	ManualKey: true,
})

var callTable = model.NewTable(model.TableSpec{
	Name:      callsTable,
	New:       func() model.Entity { return new(Call) },
	ManualKey: true,
})

// arandu:begin custom

// The table names, declared once for the migrations and the queries.
const (
	endpointsTable  = "webhook_server_endpoints"
	callsTable      = "webhook_client_calls"
	deliveriesTable = "webhook_server_deliveries"
	attemptsTable   = "webhook_server_delivery_attempts"
)

// maxDeliveryIDLen is the width of a delivery's id and event id, which the
// caller may choose.
const maxDeliveryIDLen = 128

// maxSealedLen is the width of an endpoint's sealed previous secrets and of
// its policy, which are short enough for a column with a default on every
// engine.
const maxSealedLen = 2048

// MaxPreviousSecrets is how many previous secrets an endpoint keeps signing
// with at once.
const MaxPreviousSecrets = 5

// maxIdentifierLen is the width of an identifier column.
const maxIdentifierLen = 64

// AllEvents is the subscription to every event.
const AllEvents = "*"

// EventList returns the events the endpoint subscribes to.
func (e Endpoint) EventList() []string {
	var out []string
	for _, name := range strings.Split(e.Events, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// Receives reports whether an event of this name goes to the endpoint.
func (e Endpoint) Receives(event string) bool {
	if !e.Active {
		return false
	}
	for _, name := range e.EventList() {
		if name == AllEvents || name == event {
			return true
		}
	}
	return false
}

// signerFor is what the signer column of the previous release holds for a dialect.
func signerFor(dialect string) string {
	if dialect == DialectHMAC {
		return SignerHMAC
	}
	return SignerArandu
}

// Enable turns the endpoint on and clears what the engine recorded when it
// turned it off.
func (e *Endpoint) Enable(now time.Time) {
	e.Active, e.ConsecutiveFailures, e.DisabledAt, e.DisabledReason, e.UpdatedAt = true, 0, nil, "", now
}

// Disable turns the endpoint off, and keeps why when the engine did it.
func (e *Endpoint) Disable(reason string, now time.Time) {
	e.Active, e.UpdatedAt = false, now
	if reason != "" {
		at := now
		e.DisabledAt, e.DisabledReason = &at, reason
	}
}

// DisabledByFailures is the reason the engine records when an endpoint's
// deliveries gave up DisableAfter times in a row.
const DisabledByFailures = "consecutive_failures"

// ShouldDisable reports whether the engine turns the endpoint off: it is
// active, and disableAfter of its deliveries in a row gave up.
func (e Endpoint) ShouldDisable(disableAfter int) bool {
	return disableAfter > 0 && bool(e.Active) && e.ConsecutiveFailures >= disableAfter
}

// Waits returns the waits before each attempt after the first, as frozen
// when the delivery was recorded.
func (d Delivery) Waits() []time.Duration {
	var ms []int64
	if d.Backoff != "" {
		_ = json.Unmarshal([]byte(d.Backoff), &ms)
	}
	out := make([]time.Duration, 0, len(ms))
	for _, wait := range ms {
		out = append(out, time.Duration(wait)*time.Millisecond)
	}
	return out
}

// WaitAfter is how long the delivery waits after its attempt number n
// failed, before attempt n+1.
func (d Delivery) WaitAfter(n int64) time.Duration {
	waits := d.Waits()
	switch {
	case n >= 1 && int(n-1) < len(waits):
		return waits[n-1]
	case len(waits) > 0:
		return waits[len(waits)-1]
	}
	return 0
}

// Spent reports whether the delivery has no attempt left.
func (d Delivery) Spent() bool { return d.Attempts >= d.MaxAttempts }

// encodeWaits is the JSON a delivery freezes its waits as.
func encodeWaits(waits []time.Duration) string {
	ms := make([]int64, 0, len(waits))
	for _, wait := range waits {
		ms = append(ms, wait.Milliseconds())
	}
	encoded, _ := json.Marshal(ms)
	return string(encoded)
}

// Header returns the first value of a kept header, by any case of its name.
func (c Call) Header(name string) string {
	values := c.Headers()[strings.ToLower(name)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// Headers returns the kept headers, by lowercase name.
func (c Call) Headers() map[string][]string {
	out := map[string][]string{}
	if c.HeaderData != "" {
		_ = json.Unmarshal([]byte(c.HeaderData), &out)
	}
	return out
}

// ReceivedHeaders returns every header the call arrived with, kept or not,
// to a processor that runs while the request is answered -- a SyncProcessor.
// It is nil once the call was read back from its table: a processor on the
// queue reads Headers, which StoreHeaders chose, and HeadersSHA256.
func (c Call) ReceivedHeaders() http.Header {
	if c.received == nil {
		return nil
	}
	return c.received.Clone()
}

// HeadersDigest is the hex SHA-256 of a request's headers in one canonical
// form: every name lowercased, the names sorted, and for each a line of the
// name, ": ", its values joined by ", " in the order they arrived, and "\n".
func HeadersDigest(h http.Header) string {
	lines := map[string][]string{}
	for name, values := range h {
		lower := strings.ToLower(strings.TrimSpace(name))
		lines[lower] = append(lines[lower], values...)
	}
	names := make([]string, 0, len(lines))
	for name := range lines {
		names = append(names, name)
	}
	sort.Strings(names)
	sum := sha256.New()
	for _, name := range names {
		_, _ = sum.Write([]byte(name + ": " + strings.Join(lines[name], ", ") + "\n"))
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// Body returns the body as it arrived.
func (c Call) Body() []byte { return []byte(c.Payload) }

// JSON decodes a JSON body into v.
func (c Call) JSON(v any) error {
	if err := json.Unmarshal([]byte(c.Payload), v); err != nil {
		return fmt.Errorf("webhook: the body of call %s is not the JSON expected: %w", c.ID, err)
	}
	return nil
}

// Form parses a form-encoded body.
func (c Call) Form() (url.Values, error) { return url.ParseQuery(c.Payload) }

// Processed marks the call handled at now, and clears the last failure, as
// webhook-client's clearException.
func (c *Call) Processed(now time.Time) {
	c.Status, c.Exception, c.ProcessedAt, c.UpdatedAt = CallProcessed, "", now, now
}

// Failed records what the processing answered, as webhook-client's
// saveException. Only the message is kept: a trace names the application's
// files, and the call row is read by whoever reads the panel.
func (c *Call) Failed(err error, now time.Time) {
	message := "failed"
	if err != nil {
		message = err.Error()
	}
	if len(message) > 2000 {
		message = message[:2000]
	}
	c.Status, c.Exception, c.UpdatedAt = CallFailed, message, now
}

// keptHeaders is the JSON of the headers a receiver keeps.
func keptHeaders(h http.Header, keep []string) string {
	out := map[string][]string{}
	all := len(keep) == 1 && keep[0] == "*"
	wanted := map[string]bool{}
	for _, name := range keep {
		wanted[strings.ToLower(name)] = true
	}
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		lower := strings.ToLower(name)
		if all || wanted[lower] {
			out[lower] = append([]string(nil), h[name]...)
		}
	}
	if len(out) == 0 {
		return ""
	}
	encoded, _ := json.Marshal(out)
	return string(encoded)
}

// ErrNotFound is returned when no row matches, including when the row exists
// in another tenant. The two cases are deliberately indistinguishable.
//
// It wraps model.ErrModelNotFound, so the router answers it with 404.
var ErrNotFound = fmt.Errorf("webhook: record not found: %w", model.ErrModelNotFound)

// arandu:end custom

// EndpointResource is the list of fields one endpoint may answer with. The
// secret, the sealed headers and the tenant are not among them.
type EndpointResource struct {
	e       *Endpoint
	secret  string
	headers []string
}

// NewEndpointResource snapshots one endpoint for the response.
func NewEndpointResource(e *Endpoint) EndpointResource { return EndpointResource{e: e} }

// ToArray returns the fields that may leave, by name.
func (r EndpointResource) ToArray() map[string]any {
	if r.e == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"id": r.e.ID, "name": r.e.Name, "url": r.e.URL, "events": r.e.EventList(),
		"dialect": r.e.Dialect, "signer": r.e.Dialect, "active": bool(r.e.Active),
		"consecutive_failures": r.e.ConsecutiveFailures,
		"created_at":           r.e.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":           r.e.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if r.e.Dialect == DialectHMAC {
		out["signature_header"] = r.e.SignatureHeader
		out["include_arandu_headers"] = bool(r.e.AranduHeaders)
	}
	if r.e.DisabledAt != nil {
		out["disabled_at"] = r.e.DisabledAt.UTC().Format(time.RFC3339)
		out["disabled_reason"] = r.e.DisabledReason
	}
	if r.headers != nil {
		out["header_names"] = r.headers
	}
	if r.secret != "" {
		out["secret"] = r.secret
	}
	return out
}

// With adds nothing beside the fields.
func (r EndpointResource) With() map[string]any { return nil }

// CallResource is the list of fields one received call may answer with.
type CallResource struct{ c *Call }

// NewCallResource snapshots one call for the response.
func NewCallResource(c *Call) CallResource { return CallResource{c: c} }

// ToArray returns the fields that may leave, by name.
func (r CallResource) ToArray() map[string]any {
	if r.c == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"id": r.c.ID, "name": r.c.Name, "reference": r.c.Reference, "method": r.c.Method, "url": r.c.URL,
		"headers": r.c.Headers(), "payload": r.c.Payload, "status": string(r.c.Status),
		"remote_addr": r.c.RemoteAddr, "headers_sha256": r.c.HeadersSHA256,
		"attempts": r.c.Attempts, "exception": r.c.Exception,
		"created_at": r.c.CreatedAt.UTC().Format(time.RFC3339),
	}
	if r.c.Status == CallProcessed {
		out["processed_at"] = r.c.ProcessedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// With adds nothing beside the fields.
func (r CallResource) With() map[string]any { return nil }

// DeliveryResource is the list of fields one delivery may answer with. The
// body, the headers and the secret reference stay in the record.
type DeliveryResource struct{ d *Delivery }

// NewDeliveryResource snapshots one delivery for the response.
func NewDeliveryResource(d *Delivery) DeliveryResource { return DeliveryResource{d: d} }

// ToArray returns the fields that may leave, by name.
func (r DeliveryResource) ToArray() map[string]any {
	if r.d == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"id": r.d.ID, "event_id": r.d.EventID, "event": r.d.EventName, "endpoint_id": r.d.EndpointID,
		"status": r.d.Status, "attempts": r.d.Attempts, "max_attempts": r.d.MaxAttempts,
		"permanent": bool(r.d.Permanent), "body_sha256": r.d.BodySHA256,
		"created_at": r.d.CreatedAt.UTC().Format(time.RFC3339),
	}
	if r.d.ResponseStatus != nil {
		out["response_status"] = *r.d.ResponseStatus
	}
	if r.d.LastError != nil {
		out["last_error"] = *r.d.LastError
	}
	if r.d.NextAttemptAt != nil && r.d.Status == DeliveryPending {
		out["next_attempt_at"] = r.d.NextAttemptAt.UTC().Format(time.RFC3339)
	}
	if r.d.DeliveredAt != nil {
		out["delivered_at"] = r.d.DeliveredAt.UTC().Format(time.RFC3339)
	}
	return out
}

// With adds nothing beside the fields.
func (r DeliveryResource) With() map[string]any { return nil }

// DeliveryAttemptResource is the list of fields one attempt may answer with.
type DeliveryAttemptResource struct{ a *DeliveryAttempt }

// NewDeliveryAttemptResource snapshots one attempt for the response.
func NewDeliveryAttemptResource(a *DeliveryAttempt) DeliveryAttemptResource {
	return DeliveryAttemptResource{a: a}
}

// ToArray returns the fields that may leave, by name.
func (r DeliveryAttemptResource) ToArray() map[string]any {
	if r.a == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"id": r.a.ID, "delivery_id": r.a.DeliveryID, "attempt": r.a.Attempt, "trigger": r.a.Trigger,
		"succeeded": bool(r.a.Succeeded), "error": r.a.Error, "response": r.a.Response,
		"duration_ms": r.a.DurationMS,
		"signed_at":   r.a.SignedAt.UTC().Format(time.RFC3339),
		"created_at":  r.a.CreatedAt.UTC().Format(time.RFC3339),
	}
	if r.a.ResponseStatus != nil {
		out["response_status"] = *r.a.ResponseStatus
	}
	return out
}

// With adds nothing beside the fields.
func (r DeliveryAttemptResource) With() map[string]any { return nil }

// page is a list of resources and the cursor of the next page.
type page struct {
	items  []map[string]any
	cursor string
}

// ToArray returns the page under a single key.
func (p page) ToArray() map[string]any {
	items := p.items
	if items == nil {
		items = []map[string]any{}
	}
	return map[string]any{"items": items}
}

// With returns the cursor of the next page, and nothing when there is none.
func (p page) With() map[string]any {
	if p.cursor == "" {
		return nil
	}
	return map[string]any{"next_cursor": p.cursor}
}
