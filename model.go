package webhook

import (
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
	// Signer is how its calls are signed: SignerArandu or SignerHMAC.
	Signer string `db:"signer"`
	// SignatureHeader is the header a SignerHMAC signature travels in.
	SignatureHeader string `db:"signature_header"`
	// Secret is the sealed signing secret. It never leaves in a response.
	Secret string `db:"secret"`
	// Headers is the sealed JSON object of extra headers, empty when none.
	Headers string `db:"headers"`
	// Active is whether it receives events.
	Active Flag `db:"active"`

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
	// Method and URL are how it arrived.
	Method string `db:"method"`
	URL    string `db:"url"`
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

// The signers of an endpoint.
const (
	// SignerArandu signs with hesape/webhook's scheme: X-Arandu-Signature,
	// sha256= over the timestamp, the delivery id and the body.
	SignerArandu = "arandu"
	// SignerHMAC adds webhook-server's DefaultSigner: the hex HMAC-SHA256 of
	// the body, in the endpoint's SignatureHeader.
	SignerHMAC = "hmac"
)

// Delivery is the record hesape/webhook keeps of one call to one endpoint:
// its status, its attempts, the receiver's last answer. This package reads it
// and never writes it; the worker does.
//
// Deliveries, DeliveryQuery and DeliveryCollection are generated beside this
// file, in DeliveryQuery.go, by aru model:build.
type Delivery struct {
	model.Model

	ID       string `db:"id"`
	TenantID string `db:"tenant_id"`

	EventID    string `db:"event_id"`
	EventName  string `db:"event_name"`
	EndpointID string `db:"endpoint_id"`
	URL        string `db:"url"`
	// Status is pending, processing, delivered or failed.
	Status   string `db:"status"`
	Attempts int64  `db:"attempts"`
	// Permanent is a failure retrying cannot fix.
	Permanent      Flag       `db:"permanent"`
	ResponseStatus *int64     `db:"response_status"`
	LastError      *string    `db:"last_error"`
	CreatedAt      time.Time  `db:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"`
	DeliveredAt    *time.Time `db:"delivered_at"`
}

var deliveryTable = model.NewTable(model.TableSpec{
	Name:      "webhook_deliveries",
	New:       func() model.Entity { return new(Delivery) },
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
	endpointsTable = "webhook_server_endpoints"
	callsTable     = "webhook_client_calls"
)

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
		"signer": r.e.Signer, "active": bool(r.e.Active),
		"created_at": r.e.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at": r.e.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if r.e.Signer == SignerHMAC {
		out["signature_header"] = r.e.SignatureHeader
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
		"id": r.c.ID, "name": r.c.Name, "method": r.c.Method, "url": r.c.URL,
		"headers": r.c.Headers(), "payload": r.c.Payload, "status": string(r.c.Status),
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
// headers, the body and the secret reference stay in the record.
type DeliveryResource struct{ d *Delivery }

// NewDeliveryResource snapshots one delivery for the response.
func NewDeliveryResource(d *Delivery) DeliveryResource { return DeliveryResource{d: d} }

// ToArray returns the fields that may leave, by name.
func (r DeliveryResource) ToArray() map[string]any {
	if r.d == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"id": r.d.ID, "event_id": r.d.EventID, "event": r.d.EventName, "status": r.d.Status,
		"attempts": r.d.Attempts, "permanent": bool(r.d.Permanent),
		"created_at": r.d.CreatedAt.UTC().Format(time.RFC3339),
	}
	if r.d.ResponseStatus != nil {
		out["response_status"] = *r.d.ResponseStatus
	}
	if r.d.LastError != nil {
		out["last_error"] = *r.d.LastError
	}
	if r.d.DeliveredAt != nil {
		out["delivered_at"] = r.d.DeliveredAt.UTC().Format(time.RFC3339)
	}
	return out
}

// With adds nothing beside the fields.
func (r DeliveryResource) With() map[string]any { return nil }

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
