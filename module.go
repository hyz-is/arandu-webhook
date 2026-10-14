// Package webhook is an Arandu module for webhooks both ways, as
// spatie/laravel-webhook-server and spatie/laravel-webhook-client are in
// Laravel, in one package.
//
// Sending: endpoints a tenant subscribes to events, each with a sealed
// signing secret and sealed extra headers; the events outbox delivers to them
// through hesape/webhook -- one durable record and one queued job per event
// and endpoint, a signed request through a transport that refuses private
// addresses, retries with backoff and Retry-After. Outgoing builds a call in
// code, as webhook-server's WebhookCall. An endpoint signs with hesape's
// scheme or adds webhook-server's DefaultSigner: the hex HMAC-SHA256 of the
// body.
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
//	server.go     -> sending: the Manager underneath, Outgoing, the resolver
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
	s, err := newSender(db, cfg, seal)
	if err != nil {
		return nil, err
	}
	c := newClient(db, cfg)
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

// Manager is hesape/webhook's Manager underneath, for an application that
// dispatches to endpoints of its own.
func (m *Module) Manager() *hwebhook.Manager { return m.sender.manager }

// Publisher is the events outbox's listener that delivers each event to the
// tenant's endpoints subscribed to it. The application adds it to its relay's
// publishers.
func (m *Module) Publisher() events.Publisher {
	return hwebhook.NewPublisher(m.sender.manager, m.sender)
}

// Outgoing starts a call built in code, as webhook-server's
// WebhookCall::create.
func (m *Module) Outgoing() *Outgoing { return &Outgoing{s: m.sender} }

// ReceivePrefix is the path the receivers answer under, for the
// application's CSRF exemption.
func (m *Module) ReceivePrefix() string { return m.cfg.ReceivePrefix }

// RegisterJobHandlers gives the worker the deliveries and the processing of
// received calls. The worker is the application's, started by its worker
// command.
func (m *Module) RegisterJobHandlers(worker *queue.Worker) error {
	if worker == nil {
		return errors.New("webhook: RegisterJobHandlers needs a worker")
	}
	if err := m.sender.manager.RegisterJobHandlers(worker); err != nil {
		return err
	}
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
			r.Action(method, m.cfg.ReceivePrefix+"/"+rc.Name, handler).Name(name)
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
	if err := m.endpoints.Test(ctx.Ctx(), who, ctx.Param("id")); err != nil {
		return err
	}
	return ctx.Status(stdhttp.StatusAccepted)
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
	active := strings.ToLower(ctx.Input("active"))
	return EndpointRequest{
		Name: ctx.Input("name"), URL: ctx.Input("url"), Events: events,
		Signer: ctx.Input("signer"), SignatureHeader: ctx.Input("signature_header"), Headers: ctx.Input("headers"),
		Active: active == "1" || active == "true" || active == "on",
	}
}

// secretResource answers an endpoint's secret.
type secretResource string

func (s secretResource) ToArray() map[string]any { return map[string]any{"secret": string(s)} }
func (s secretResource) With() map[string]any    { return nil }

// Schedule declares the daily clean of old received calls, as
// webhook-client's model:prune of WebhookCall, in each receiver's tenant.
// CleanSpec "-" declares none.
func (m *Module) Schedule() []foundation.Task {
	if m.cfg.CleanSpec == "-" || len(m.cfg.Receivers) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var tenants []string
	for _, rc := range m.cfg.Receivers {
		if !seen[rc.Tenant] {
			seen[rc.Tenant] = true
			tenants = append(tenants, rc.Tenant)
		}
	}
	days := m.cfg.DeleteAfterDays
	return []foundation.Task{{
		ID:        "webhook.calls.clean",
		Spec:      m.cfg.CleanSpec,
		Scope:     foundation.Global,
		Timeout:   10 * time.Minute,
		Singleton: true,
		Action:    CallClean,
		Run: func(ctx context.Context, _ security.Grant) error {
			cutoff := time.Now().UTC().AddDate(0, 0, -days)
			for _, tenant := range tenants {
				//arandu:system-grant the application named this tenant in a Receiver; the clean removes only its calls older than DeleteAfterDays.
				g := security.SystemGrant(CallClean, tenant)
				if _, err := m.calls.clean(ctx, g, cutoff); err != nil {
					return err
				}
			}
			return nil
		},
	}}
}

// Migrations declares the schema this module owns: its two tables, and the
// deliveries table of hesape/webhook underneath. An application that already
// runs hesape/webhook's Manager has that migration applied, and the migrator
// skips a name it has run.
func (m *Module) Migrations() []foundation.Migration {
	return append([]foundation.Migration{createEndpoints{}, createCalls{}}, m.sender.manager.Migrations()...)
}

var (
	_ migrations.ReversibleMigration = createEndpoints{}
	_ migrations.ReversibleMigration = createCalls{}
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
