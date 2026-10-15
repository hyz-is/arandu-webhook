// Package webhook is an Arandu module for webhooks both ways, as
// spatie/laravel-webhook-server and spatie/laravel-webhook-client are in
// Laravel, in one package.
//
// Sending: endpoints a tenant subscribes to events, each with a sealed
// signing secret and sealed extra headers. The module owns the delivery: one
// durable record per message and endpoint, its body frozen, written in the
// same transaction as the job that makes its first attempt; every attempt
// signed when it is made, in the endpoint's dialect -- hesape's Arandu scheme,
// webhook-server's HMAC of the body, or Standard Webhooks -- through a
// transport that refuses internal addresses, under a Policy that says how
// many attempts, how far apart, and what counts as a failure. The events
// outbox delivers through Publisher, Send delivers a message the application
// built, and Outgoing builds a call in code, as webhook-server's WebhookCall.
//
// Receiving: a Receiver per system that calls the application, mounted at
// ReceivePrefix/<name>, as webhook-client's configs. A call is checked against
// its signature, offered to the Profile, stored with the headers the receiver
// keeps, and processed on the queue by the receiver's Processor; the sender
// gets the Responder's answer at once. Old calls are cleaned on a schedule.
//
// The files are laid out by role:
//
//	module.go     -> registration, routes, handlers, jobs, schedule, migrations
//	config.go     -> what the application passes in
//	model.go      -> the endpoint, the received call, the delivery record
//	policy.go     -> who may do what
//	service.go    -> the use cases, and Model access after authorization
//	server.go     -> sending: recording deliveries, Publisher, Send, Outgoing
//	delivery.go   -> the attempts: claim, request, settle, retry, clean
//	dialect.go    -> how each dialect signs a request
//	transport.go  -> the guarded client the attempts go out on
//	audit.go      -> the management events stored in the outbox
//	client.go     -> receiving: the pipeline and its processing job
//	signature.go  -> the signers, the validators and the seal
package webhook

import (
	"context"
	"errors"
	"fmt"
	stdhttp "net/http"
	"strings"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/foundation"
	fhttp "github.com/arandu-io/framework/http"
	"github.com/arandu-io/framework/http/middleware"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/database/migrations"
	"github.com/arandu-io/hesape/database/schema"
	"github.com/arandu-io/hesape/events"
	hhttp "github.com/arandu-io/hesape/http"
	"github.com/arandu-io/hesape/queue"
	hwebhook "github.com/arandu-io/hesape/webhook"
)

// Module is what the application registers.
type Module struct {
	cfg       Config
	sessions  *security.SessionStore
	sender    *sender
	client    *client
	endpoints *EndpointService
	calls     *CallService
}

// Compile-time proof that the module honors the contracts it claims.
var (
	_ foundation.Module      = (*Module)(nil)
	_ foundation.Migratable  = (*Module)(nil)
	_ foundation.Schedulable = (*Module)(nil)
)

// New returns the module, or the reason it cannot be built.
//
// sessions is where the management routes take their subject from; nil
// mounts none of them, for an application that manages endpoints from its own
// screens through the services. The receivers need no session.
func New(cfg Config, db *data.DB, sessions *security.SessionStore) (*Module, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if db == nil {
		return nil, errors.New("webhook: New needs a database handle: the endpoints, the received calls and the deliveries are kept in tables")
	}
	cfg = cfg.withDefaults()
	seal, err := newSealer(cfg.Key)
	if err != nil {
		return nil, err
	}
	audit := newAuditor(db, cfg.Server.Now)
	s, err := newSender(db, cfg, seal, audit)
	if err != nil {
		return nil, err
	}
	c := newClient(db, cfg, audit)
	return &Module{
		cfg: cfg, sessions: sessions, sender: s, client: c,
		endpoints: newEndpointService(db, s), calls: newCallService(db, c),
	}, nil
}

// Name is the module identifier.
func (m *Module) Name() string { return "webhook" }

// EndpointService is the sending side's use cases, for an application that
// calls them from its own screens. Every method asks the policy.
func (m *Module) EndpointService() *EndpointService { return m.endpoints }

// CallService is the receiving side's record, for an application that reads
// it from its own screens. Every method asks the policy.
func (m *Module) CallService() *CallService { return m.calls }

// Publisher is the events outbox's listener that delivers each event to the
// tenant's active endpoints subscribed to it. The application adds it to its
// relay's publishers. The module's own management events, which travel on
// the same outbox, are not delivered.
func (m *Module) Publisher() events.Publisher { return publisher{s: m.sender} }

// Send records one message to one of the tenant's endpoints, whatever it
// subscribes to, and queues its first attempt in the same transaction: the
// message the application built, its id and its body sent exactly as given
// on every attempt. g carries DeliveryDispatch for the tenant: the
// application decided to send, and that decision is the Grant. A second
// message with the same EventID to the same endpoint answers the first
// delivery and sends nothing.
func (m *Module) Send(ctx context.Context, g security.Grant, endpointID string, msg Message) (*Delivery, error) {
	return m.sender.send(ctx, g, endpointID, msg)
}

// Outgoing starts a call built in code, as webhook-server's
// WebhookCall::create.
func (m *Module) Outgoing() *Outgoing { return &Outgoing{s: m.sender} }

// ReceivePrefix is the path the receivers answer under, for the
// application's CSRF exemption.
func (m *Module) ReceivePrefix() string { return m.cfg.ReceivePrefix }

// ReceivePaths are the path prefixes the receivers answer under, for the
// application's CSRF exemption: ReceivePrefix, and the fixed part of every
// Mount, up to its first parameter.
//
//	middleware.CSRFExcept(webhookModule.ReceivePaths()...)
func (m *Module) ReceivePaths() []string {
	out := []string{m.cfg.ReceivePrefix + "/"}
	seen := map[string]bool{out[0]: true}
	for _, rc := range m.cfg.Receivers {
		if rc.Mount == "" {
			continue
		}
		fixed := rc.Mount
		if i := strings.Index(fixed, "{"); i >= 0 {
			fixed = fixed[:strings.LastIndex(fixed[:i], "/")+1]
		}
		if !seen[fixed] {
			seen[fixed] = true
			out = append(out, fixed)
		}
	}
	return out
}

// RegisterJobHandlers gives the worker the attempts of the deliveries and
// the processing of received calls. The worker is the application's,
// started by its worker command, on Server.Queue.
func (m *Module) RegisterJobHandlers(worker *queue.Worker) error {
	if worker == nil {
		return errors.New("webhook: RegisterJobHandlers needs a worker")
	}
	worker.HandleFunc(DeliverJob, m.sender.handle)
	worker.HandleFunc(ProcessJob, m.client.handle)
	return nil
}

// Routes registers the receivers, and the management routes behind
// RequireAuth when the module has a session store.
//
// A receiver is reached by a system with no session: its signature admits it.
// Its route is registered on r itself, and the guarded group is built after,
// so no management route lands outside the guard.
func (m *Module) Routes(r *fhttp.Router) {
	for _, rc := range m.cfg.Receivers {
		rc := m.client.receivers[rc.Name]
		handler := func(ctx *fhttp.Context) error { return m.client.receive(ctx.Response, ctx.Request, rc) }
		for i, method := range rc.Methods {
			name := "webhook.receive." + rc.Name
			if i > 0 {
				name += "." + strings.ToLower(method)
			}
			r.Action(method, rc.route(m.cfg.ReceivePrefix), handler).Name(name)
		}
	}
	if m.sessions == nil {
		return
	}

	r = r.Group("", middleware.RequireAuth(m.sessions))

	p := m.cfg.Prefix
	r.Action(stdhttp.MethodGet, p+"/endpoints", m.endpointIndex).Name("webhook.endpoints.index")
	r.Action(stdhttp.MethodPost, p+"/endpoints", m.endpointStore).Name("webhook.endpoints.store")
	r.Action(stdhttp.MethodGet, p+"/endpoints/{id}", m.endpointShow).Name("webhook.endpoints.show")
	r.Action(stdhttp.MethodPut, p+"/endpoints/{id}", m.endpointUpdate).Name("webhook.endpoints.update")
	r.Action(stdhttp.MethodDelete, p+"/endpoints/{id}", m.endpointDestroy).Name("webhook.endpoints.destroy")
	r.Action(stdhttp.MethodGet, p+"/endpoints/{id}/secret", m.endpointSecret).Name("webhook.endpoints.secret")
	r.Action(stdhttp.MethodPost, p+"/endpoints/{id}/test", m.endpointTest).Name("webhook.endpoints.test")
	r.Action(stdhttp.MethodGet, p+"/endpoints/{id}/deliveries", m.endpointDeliveries).Name("webhook.endpoints.deliveries")
	r.Action(stdhttp.MethodPost, p+"/endpoints/{id}/rotate", m.endpointRotate).Name("webhook.endpoints.rotate")
	r.Action(stdhttp.MethodPost, p+"/endpoints/{id}/enable", m.endpointEnable).Name("webhook.endpoints.enable")
	r.Action(stdhttp.MethodPost, p+"/endpoints/{id}/disable", m.endpointDisable).Name("webhook.endpoints.disable")
	r.Action(stdhttp.MethodGet, p+"/deliveries/{id}", m.deliveryShow).Name("webhook.deliveries.show")
	r.Action(stdhttp.MethodGet, p+"/deliveries/{id}/attempts", m.deliveryAttempts).Name("webhook.deliveries.attempts")
	r.Action(stdhttp.MethodPost, p+"/deliveries/{id}/redeliver", m.deliveryRedeliver).Name("webhook.deliveries.redeliver")
	r.Action(stdhttp.MethodGet, p+"/calls", m.callIndex).Name("webhook.calls.index")
	r.Action(stdhttp.MethodGet, p+"/calls/{id}", m.callShow).Name("webhook.calls.show")
	r.Action(stdhttp.MethodPost, p+"/calls/{id}/process", m.callProcess).Name("webhook.calls.process")
}

// Handlers are thin: read the input and who is asking, ask the service,
// answer. An error is returned as it is, and the router answers it --
// validation.Errors with 422 or the form again, ErrNotFound with 404, a policy
// refusal with 403.

func (m *Module) endpointIndex(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	rows, err := m.endpoints.List(ctx.Ctx(), who, data.Query{Cursor: ctx.Query("cursor"), Limit: m.cfg.PageSize})
	if err != nil {
		return err
	}
	out := page{}
	for _, row := range rows {
		out.items = append(out.items, NewEndpointResource(row).ToArray())
	}
	if len(rows) == m.cfg.PageSize {
		out.cursor = rows[len(rows)-1].ID
	}
	return ctx.JSON(stdhttp.StatusOK, out)
}

func (m *Module) endpointStore(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	record, secret, err := m.endpoints.Create(ctx.Ctx(), who, endpointRequest(ctx))
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusCreated, EndpointResource{e: record, secret: secret})
}

func (m *Module) endpointShow(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	record, err := m.endpoints.Find(ctx.Ctx(), who, ctx.Param("id"))
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusOK, NewEndpointResource(record))
}

func (m *Module) endpointUpdate(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	record, err := m.endpoints.Update(ctx.Ctx(), who, ctx.Param("id"), endpointRequest(ctx))
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusOK, NewEndpointResource(record))
}

func (m *Module) endpointDestroy(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	if err := m.endpoints.Delete(ctx.Ctx(), who, ctx.Param("id")); err != nil {
		return err
	}
	return ctx.Status(stdhttp.StatusNoContent)
}

func (m *Module) endpointSecret(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	secret, err := m.endpoints.Secret(ctx.Ctx(), who, ctx.Param("id"))
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusOK, secretResource(secret))
}

func (m *Module) endpointTest(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	delivery, err := m.endpoints.Test(ctx.Ctx(), who, ctx.Param("id"))
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusAccepted, NewDeliveryResource(delivery))
}

func (m *Module) endpointRotate(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	secret, err := m.endpoints.Rotate(ctx.Ctx(), who, ctx.Param("id"), DefaultRotationOverlap)
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusOK, secretResource(secret))
}

func (m *Module) endpointEnable(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	record, err := m.endpoints.Enable(ctx.Ctx(), who, ctx.Param("id"))
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusOK, NewEndpointResource(record))
}

func (m *Module) endpointDisable(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	record, err := m.endpoints.Disable(ctx.Ctx(), who, ctx.Param("id"))
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusOK, NewEndpointResource(record))
}

func (m *Module) deliveryShow(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	delivery, err := m.endpoints.Delivery(ctx.Ctx(), who, ctx.Param("id"))
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusOK, NewDeliveryResource(delivery))
}

func (m *Module) deliveryAttempts(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	rows, err := m.endpoints.Attempts(ctx.Ctx(), who, ctx.Param("id"))
	if err != nil {
		return err
	}
	out := page{}
	for _, row := range rows {
		out.items = append(out.items, NewDeliveryAttemptResource(row).ToArray())
	}
	return ctx.JSON(stdhttp.StatusOK, out)
}

func (m *Module) deliveryRedeliver(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	delivery, err := m.endpoints.Redeliver(ctx.Ctx(), who, ctx.Param("id"))
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusAccepted, NewDeliveryResource(delivery))
}

func (m *Module) endpointDeliveries(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	rows, err := m.endpoints.Deliveries(ctx.Ctx(), who, ctx.Param("id"), m.cfg.PageSize)
	if err != nil {
		return err
	}
	out := page{}
	for _, row := range rows {
		out.items = append(out.items, NewDeliveryResource(row).ToArray())
	}
	return ctx.JSON(stdhttp.StatusOK, out)
}

func (m *Module) callIndex(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	rows, err := m.calls.List(ctx.Ctx(), who, CallFilter{Name: ctx.Query("name"), Status: CallStatus(ctx.Query("status"))},
		data.Query{Cursor: ctx.Query("cursor"), Limit: m.cfg.PageSize})
	if err != nil {
		return err
	}
	out := page{}
	for _, row := range rows {
		out.items = append(out.items, NewCallResource(row).ToArray())
	}
	if len(rows) == m.cfg.PageSize {
		out.cursor = rows[len(rows)-1].ID
	}
	return ctx.JSON(stdhttp.StatusOK, out)
}

func (m *Module) callShow(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	record, err := m.calls.Find(ctx.Ctx(), who, ctx.Param("id"))
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusOK, NewCallResource(record))
}

func (m *Module) callProcess(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	if err := m.calls.Process(ctx.Ctx(), who, ctx.Param("id")); err != nil {
		return err
	}
	return ctx.Status(stdhttp.StatusAccepted)
}

// endpointRequest reads an endpoint from a form or a JSON body. events is a
// list, or one comma-separated text.
func endpointRequest(ctx *fhttp.Context) EndpointRequest {
	in := hhttp.NewRequest(ctx.Request)
	var events []string
	switch v := in.Input("events").(type) {
	case []any:
		for _, item := range v {
			events = append(events, fmt.Sprint(item))
		}
	case []string:
		events = v
	case string:
		events = strings.Split(v, ",")
	}
	yes := func(field string) bool {
		value := strings.ToLower(ctx.Input(field))
		return value == "1" || value == "true" || value == "on"
	}
	return EndpointRequest{
		Name: ctx.Input("name"), URL: ctx.Input("url"), Events: events,
		Dialect: ctx.Input("dialect"), Signer: ctx.Input("signer"), SignatureHeader: ctx.Input("signature_header"),
		WithoutAranduHeaders: yes("without_arandu_headers"), Headers: ctx.Input("headers"), Active: yes("active"),
	}
}

// secretResource answers an endpoint's secret.
type secretResource string

func (s secretResource) ToArray() map[string]any { return map[string]any{"secret": string(s)} }
func (s secretResource) With() map[string]any    { return nil }

// Schedule declares the daily cleans, each run in every tenant: of old
// received calls, as webhook-client's model:prune of WebhookCall -- every
// tenant, because a receiver with Resolve takes calls for any of them -- and
// of the deliveries settled longer ago than Server.Retention, with their
// attempts. CleanSpec "-" declares none.
func (m *Module) Schedule() []foundation.Task {
	if m.cfg.CleanSpec == "-" {
		return nil
	}
	retention := m.cfg.Server.Retention
	tasks := []foundation.Task{{
		ID:        "webhook.deliveries.clean",
		Spec:      m.cfg.CleanSpec,
		Scope:     foundation.PerTenant,
		Timeout:   10 * time.Minute,
		Singleton: true,
		Action:    DeliveryClean,
		Run: func(ctx context.Context, g security.Grant) error {
			return m.sender.clean(ctx, g, m.sender.clock().Add(-retention))
		},
	}}
	if len(m.cfg.Receivers) == 0 {
		return tasks
	}
	days := m.cfg.DeleteAfterDays
	return append(tasks, foundation.Task{
		ID:        "webhook.calls.clean",
		Spec:      m.cfg.CleanSpec,
		Scope:     foundation.PerTenant,
		Timeout:   10 * time.Minute,
		Singleton: true,
		Action:    CallClean,
		Run: func(ctx context.Context, g security.Grant) error {
			_, err := m.calls.clean(ctx, g, time.Now().UTC().AddDate(0, 0, -days))
			return err
		},
	})
}

// Migrations declares the schema this module owns: the endpoints, the
// received calls, the deliveries and their attempts. The jobs table is the
// queue's, and the outbox the management events are stored in is hesape's
// events, both migrated by the application.
func (m *Module) Migrations() []foundation.Migration {
	return []foundation.Migration{createEndpoints{}, createCalls{}, extendEndpoints{}, createDeliveries{}, createAttempts{}, addCallReference{}}
}

var (
	_ migrations.ReversibleMigration = createEndpoints{}
	_ migrations.ReversibleMigration = createCalls{}
	_ migrations.ReversibleMigration = extendEndpoints{}
	_ migrations.ReversibleMigration = createDeliveries{}
	_ migrations.ReversibleMigration = createAttempts{}
	_ migrations.ReversibleMigration = addCallReference{}
)

// createEndpoints is the sending side's endpoints.
type createEndpoints struct{ migrations.BaseMigration }

// GetName is the migration's identity, and it carries the order.
func (createEndpoints) GetName() string { return "20261014_0001_create_webhook_server_endpoints" }

// Up creates the table.
func (createEndpoints) Up(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Create(ctx, endpointsTable, func(table *schema.Blueprint) {
		table.String("id", maxIdentifierLen).Primary()
		table.String("tenant_id", maxIdentifierLen)
		table.String("name", 120)
		table.String("url", hwebhook.MaxURLLength)
		table.Text("events")
		table.String("signer", 16)
		table.String("signature_header", 64).Default("")
		table.Text("secret")
		table.Text("headers")
		table.UnsignedSmallInteger("active").Default(1)
		table.Timestamp("created_at")
		table.Timestamp("updated_at")
		table.Index([]string{"tenant_id", "name", "id"}, "webhook_server_endpoints_name_idx")
		table.Index([]string{"tenant_id", "active"}, "webhook_server_endpoints_active_idx")
	})
}

// Down drops the table.
func (createEndpoints) Down(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().DropIfExists(ctx, endpointsTable)
}

// createCalls is the receiving side's calls.
type createCalls struct{ migrations.BaseMigration }

// GetName is the migration's identity, and it carries the order.
func (createCalls) GetName() string { return "20261014_0002_create_webhook_client_calls" }

// Up creates the table.
func (createCalls) Up(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Create(ctx, callsTable, func(table *schema.Blueprint) {
		table.String("id", maxIdentifierLen).Primary()
		table.String("tenant_id", maxIdentifierLen)
		table.String("name", 64)
		table.String("method", 8)
		table.String("url", hwebhook.MaxURLLength)
		table.Text("headers")
		table.Text("payload")
		table.String("status", 16)
		table.Integer("attempts").Default(0)
		table.Text("exception")
		table.Timestamp("processed_at")
		table.Timestamp("created_at")
		table.Timestamp("updated_at")
		table.Index([]string{"tenant_id", "created_at", "id"}, "webhook_client_calls_created_idx")
		table.Index([]string{"tenant_id", "name", "status"}, "webhook_client_calls_status_idx")
	})
}

// Down drops the table.
func (createCalls) Down(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().DropIfExists(ctx, callsTable)
}

// extendEndpoints gives the endpoints their dialect, their previous secrets,
// their own policy and what the engine records when it turns one off. Every
// column has a default, so a row a binary of the previous release writes during
// a rollout reads back; the dialect starts as the signer that release wrote,
// and the signer column stays.
type extendEndpoints struct{ migrations.BaseMigration }

// GetName is the migration's identity, and it carries the order.
func (extendEndpoints) GetName() string {
	return "20261014_0003_add_dialect_and_policy_to_webhook_server_endpoints"
}

// Up adds the columns and fills them for the rows already there.
func (extendEndpoints) Up(ctx context.Context, conn migrations.Connection) error {
	err := conn.Schema().Table(ctx, endpointsTable, func(table *schema.Blueprint) {
		table.String("dialect", 32).Default(DialectArandu)
		table.UnsignedSmallInteger("include_arandu_headers").Default(1)
		table.String("previous_secrets", maxSealedLen).Default("")
		table.String("policy", maxSealedLen).Default("")
		table.Integer("consecutive_failures").Default(0)
		table.Timestamp("disabled_at").Nullable()
		table.String("disabled_reason", 64).Default("")
	})
	if err != nil {
		return err
	}
	_, err = conn.Statement(ctx, "UPDATE "+endpointsTable+" SET dialect = signer", nil)
	return err
}

// Down drops the columns.
func (extendEndpoints) Down(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Table(ctx, endpointsTable, func(table *schema.Blueprint) {
		table.DropColumn("dialect", "include_arandu_headers", "previous_secrets", "policy",
			"consecutive_failures", "disabled_at", "disabled_reason")
	})
}

// createDeliveries is the deliveries this module records and attempts.
type createDeliveries struct{ migrations.BaseMigration }

// GetName is the migration's identity, and it carries the order.
func (createDeliveries) GetName() string { return "20261014_0004_create_webhook_server_deliveries" }

// Up creates the table.
func (createDeliveries) Up(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Create(ctx, deliveriesTable, func(table *schema.Blueprint) {
		table.String("id", maxDeliveryIDLen).Primary()
		table.String("tenant_id", maxIdentifierLen)
		table.String("event_id", maxDeliveryIDLen)
		table.String("event_name", 255)
		table.String("endpoint_id", maxIdentifierLen)
		table.String("url", hwebhook.MaxURLLength)
		table.String("dialect", 32)
		table.MediumText("body")
		table.String("body_sha256", 64)
		table.Text("headers")
		table.String("secret_ref", 128)
		table.String("signature_header", 64).Default("")
		table.UnsignedSmallInteger("include_arandu_headers").Default(1)
		table.String("status", 16)
		table.Integer("attempts").Default(0)
		table.Integer("max_attempts")
		table.Text("backoff")
		table.UnsignedSmallInteger("permanent").Default(0)
		table.Timestamp("next_attempt_at").Nullable()
		table.Integer("response_status").Nullable()
		table.Text("last_error").Nullable()
		table.String("claim_token", maxIdentifierLen).Nullable()
		table.Timestamp("lease_until").Nullable()
		table.Timestamp("created_at")
		table.Timestamp("updated_at")
		table.Timestamp("delivered_at").Nullable()
		table.Unique([]string{"tenant_id", "event_id", "endpoint_id"}, "webhook_server_deliveries_event_endpoint_uidx")
		table.Index([]string{"tenant_id", "endpoint_id", "created_at", "id"}, "webhook_server_deliveries_endpoint_idx")
		table.Index([]string{"tenant_id", "status", "next_attempt_at"}, "webhook_server_deliveries_due_idx")
		table.Index([]string{"tenant_id", "created_at"}, "webhook_server_deliveries_retention_idx")
	})
}

// Down drops the table.
func (createDeliveries) Down(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().DropIfExists(ctx, deliveriesTable)
}

// createAttempts is the history of every attempt of a delivery.
type createAttempts struct{ migrations.BaseMigration }

// GetName is the migration's identity, and it carries the order.
func (createAttempts) GetName() string {
	return "20261014_0005_create_webhook_server_delivery_attempts"
}

// Up creates the table.
func (createAttempts) Up(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Create(ctx, attemptsTable, func(table *schema.Blueprint) {
		table.String("id", maxIdentifierLen).Primary()
		table.String("tenant_id", maxIdentifierLen)
		table.String("delivery_id", maxDeliveryIDLen)
		table.String("endpoint_id", maxIdentifierLen)
		table.Integer("attempt")
		table.String("triggered_by", 16)
		table.UnsignedSmallInteger("succeeded").Default(0)
		table.Integer("response_status").Nullable()
		table.String("error", 64).Default("")
		table.Text("response")
		table.BigInteger("duration_ms").Default(0)
		table.Timestamp("signed_at")
		table.Timestamp("created_at")
		table.Unique([]string{"tenant_id", "delivery_id", "attempt"}, "webhook_server_delivery_attempts_uidx")
		table.Index([]string{"tenant_id", "created_at"}, "webhook_server_delivery_attempts_retention_idx")
	})
}

// Down drops the table.
func (createAttempts) Down(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().DropIfExists(ctx, attemptsTable)
}

// addCallReference gives a received call the record its receiver resolved it
// to. The column has a default, so the calls already stored, and a row a
// binary of the previous release writes during a rollout, read back.
type addCallReference struct{ migrations.BaseMigration }

// GetName is the migration's identity, and it carries the order.
func (addCallReference) GetName() string {
	return "20261015_0006_add_reference_to_webhook_client_calls"
}

// Up adds the column.
func (addCallReference) Up(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Table(ctx, callsTable, func(table *schema.Blueprint) {
		table.String("reference", 255).Default("")
	})
}

// Down drops the column.
func (addCallReference) Down(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Table(ctx, callsTable, func(table *schema.Blueprint) {
		table.DropColumn("reference")
	})
}
