package webhook

import (
	"context"
	"strings"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/events"
)

// The events every management act stores in the application's outbox, in the
// same transaction as the act. The outbox row carries the tenant, the subject
// that was authorized and the action, so an events.Publisher such as
// arandu-activitylog's EventRecorder writes who did what to which endpoint
// without this module depending on it. A payload never carries a secret, a
// signature or a header's value.
const (
	// EventEndpointCreated is an endpoint added, with its name, address,
	// events and dialect.
	EventEndpointCreated = "webhook.endpoint.created"
	// EventEndpointUpdated is an endpoint changed, with what it was and what
	// it is.
	EventEndpointUpdated = "webhook.endpoint.updated"
	// EventEndpointDeleted is an endpoint removed.
	EventEndpointDeleted = "webhook.endpoint.deleted"
	// EventEndpointEnabled is an endpoint turned on.
	EventEndpointEnabled = "webhook.endpoint.enabled"
	// EventEndpointDisabled is an endpoint turned off, by a person or by the
	// engine after DisableAfter deliveries in a row gave up; the reason says
	// which.
	EventEndpointDisabled = "webhook.endpoint.disabled"
	// EventEndpointImported is an endpoint stored with an id and secrets it
	// already had.
	EventEndpointImported = "webhook.endpoint.imported"
	// EventSecretRevealed is an endpoint's secret read in clear.
	EventSecretRevealed = "webhook.endpoint.secret_revealed"
	// EventSecretRotated is an endpoint given a new secret, with when the
	// previous one retires.
	EventSecretRotated = "webhook.endpoint.secret_rotated"
	// EventEndpointTested is a test call queued to an endpoint.
	EventEndpointTested = "webhook.endpoint.tested"
	// EventDeliveryRedelivered is a delivery sent again by somebody.
	EventDeliveryRedelivered = "webhook.delivery.redelivered"
	// EventCallReprocessed is a received call sent to its processor again.
	EventCallReprocessed = "webhook.call.reprocessed"
)

// auditEvent reports whether an event name is one of this module's own
// management events. The Publisher does not deliver them to endpoints: they
// travel on the application's outbox to whoever logs them, and an endpoint
// subscribed to every event would otherwise be told about its own secret
// being rotated.
func auditEvent(name string) bool {
	switch name {
	case EventEndpointCreated, EventEndpointUpdated, EventEndpointDeleted, EventEndpointEnabled,
		EventEndpointDisabled, EventEndpointImported, EventSecretRevealed, EventSecretRotated,
		EventEndpointTested, EventDeliveryRedelivered, EventCallReprocessed:
		return true
	}
	return false
}

// The aggregates the events are about.
const (
	aggregateEndpoint = "webhook_endpoint"
	aggregateDelivery = "webhook_delivery"
	aggregateCall     = "webhook_call"
)

// auditor stores the management events in the outbox on the module's
// database handle.
type auditor struct {
	outbox *events.Outbox
	now    func() time.Time
}

func newAuditor(db *data.DB, now func() time.Time) *auditor {
	return &auditor{outbox: events.NewOutbox(outboxHandle{db}), now: now}
}

// record stores one event. It runs inside the transaction of the act it
// records, and fails it when it cannot be stored: an act the log does not
// know of is an act that did not happen.
func (a *auditor) record(ctx context.Context, g security.Grant, name, aggregate, id string, payload map[string]any) error {
	return a.outbox.Store(ctx, g, []events.Event{{
		Name: name, Aggregate: aggregate, AggregateID: id, Payload: payload, OccurredAt: a.now().UTC(),
	}})
}

// outboxHandle is the module's handle as the outbox reads it.
type outboxHandle struct{ *data.DB }

// InTransaction reports whether ctx is inside a transaction on the handle.
func (h outboxHandle) InTransaction(ctx context.Context) bool { return data.InTransaction(ctx, h.DB) }

// endpointFacts is what the log keeps of an endpoint: nothing sealed.
func endpointFacts(e *Endpoint) map[string]any {
	return map[string]any{
		"name": e.Name, "url": e.URL, "events": strings.Join(e.EventList(), ","),
		"dialect": e.Dialect, "active": bool(e.Active),
	}
}
