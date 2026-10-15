package unit_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/database/model"
	"github.com/arandu-io/hesape/database/query"

	webhook "github.com/hyz-is/arandu-webhook"
)

// The four properties this package exists to keep are checked here, against
// the code:
//
//  1. a policy allows nothing a subject was not given, and nothing across
//     tenants or to a guest;
//  2. the services authorize before constructing or running a generated query;
//  3. the tenant comes from the Grant;
//  4. nothing reaches the database without passing through the first two.
//
// The fourth is checked by the handle these tests pass in. It wraps a nil
// *sql.DB, so any statement that were issued would panic and fail the test.

const testKey = "0123456789abcdef0123456789abcdef"

var endpointActions = []security.Action{
	webhook.EndpointView, webhook.EndpointList, webhook.EndpointCreate, webhook.EndpointUpdate,
	webhook.EndpointDelete, webhook.EndpointSecret, webhook.EndpointTest, webhook.EndpointRotate,
	webhook.EndpointImport, webhook.DeliveryRedeliver,
}

// systemActions are the Grants the module issues for itself, and that no
// subject is allowed even when it carries them.
var systemActions = []security.Action{webhook.CallReceive, webhook.CallClean, webhook.DeliveryDispatch, webhook.DeliveryClean}

var callActions = []security.Action{webhook.CallView, webhook.CallList, webhook.CallProcess}

// administrator is the most privileged subject an application produces by
// role. The policies answer actions, not roles, so it is refused everything.
func administrator() security.Subject {
	return security.Subject{ID: "user-1", Tenant: "acme", Roles: []string{"admin"}, Verified: true}
}

// granted is a subject of acme given the actions.
func granted(actions ...security.Action) security.Subject {
	s := administrator()
	s.Actions = actions
	return s
}

func TestThePoliciesDenyEveryActionByDefault(t *testing.T) {
	t.Parallel()

	for _, action := range append(append([]security.Action{}, endpointActions...), systemActions...) {
		if _, err := security.Authorize(context.Background(), webhook.EndpointPolicy{}, administrator(), action, webhook.Endpoint{}); !errors.Is(err, security.ErrForbidden) {
			t.Fatalf("the endpoint policy allowed %s to a subject never given it: %v", action, err)
		}
	}
	for _, action := range append(append([]security.Action{}, callActions...), systemActions...) {
		if _, err := security.Authorize(context.Background(), webhook.CallPolicy{}, administrator(), action, webhook.Call{}); !errors.Is(err, security.ErrForbidden) {
			t.Fatalf("the call policy allowed %s to a subject never given it: %v", action, err)
		}
	}
}

func TestThePoliciesAllowWhatTheSubjectWasGiven(t *testing.T) {
	t.Parallel()

	for _, action := range endpointActions {
		if _, err := security.Authorize(context.Background(), webhook.EndpointPolicy{}, granted(action), action, webhook.Endpoint{}); err != nil {
			t.Fatalf("a subject given %s was refused it: %v", action, err)
		}
	}
	for _, action := range callActions {
		if _, err := security.Authorize(context.Background(), webhook.CallPolicy{}, granted(action), action, webhook.Call{}); err != nil {
			t.Fatalf("a subject given %s was refused it: %v", action, err)
		}
	}
}

func TestTheSystemActionsAreGivenToNobody(t *testing.T) {
	t.Parallel()

	// The receiver's, the clean's and the dispatch's own Grants. A subject
	// that somehow carried them is still refused, by both policies.
	for _, action := range systemActions {
		if _, err := security.Authorize(context.Background(), webhook.CallPolicy{}, granted(action), action, webhook.Call{}); !errors.Is(err, security.ErrForbidden) {
			t.Fatalf("a subject carrying %s was allowed it on a call: %v", action, err)
		}
		if _, err := security.Authorize(context.Background(), webhook.EndpointPolicy{}, granted(action), action, webhook.Endpoint{}); !errors.Is(err, security.ErrForbidden) {
			t.Fatalf("a subject carrying %s was allowed it on an endpoint: %v", action, err)
		}
	}
	for _, action := range webhook.Actions() {
		if slices.Contains(systemActions, action) || action == webhook.EndpointImport {
			t.Fatalf("Actions offers %s, which is not given to people", action)
		}
	}
}

func TestThePoliciesDenyARecordOfAnotherTenant(t *testing.T) {
	t.Parallel()

	everything := granted(append(endpointActions, callActions...)...)
	err := webhook.EndpointPolicy{}.Can(context.Background(), everything, webhook.EndpointView, webhook.Endpoint{ID: "e-1", TenantID: "globex"})
	if err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("the endpoint policy allowed another tenant's endpoint: %v", err)
	}
	err = webhook.CallPolicy{}.Can(context.Background(), everything, webhook.CallView, webhook.Call{ID: "c-1", TenantID: "globex"})
	if err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("the call policy allowed another tenant's call: %v", err)
	}
}

func TestThePoliciesDenyAGuest(t *testing.T) {
	t.Parallel()

	for _, action := range endpointActions {
		if _, err := security.Authorize(context.Background(), webhook.EndpointPolicy{}, security.Guest("acme"), action, webhook.Endpoint{}); !errors.Is(err, security.ErrForbidden) {
			t.Fatalf("a guest was allowed %s: %v", action, err)
		}
	}
	for _, action := range callActions {
		if _, err := security.Authorize(context.Background(), webhook.CallPolicy{}, security.Guest("acme"), action, webhook.Call{}); !errors.Is(err, security.ErrForbidden) {
			t.Fatalf("a guest was allowed %s: %v", action, err)
		}
	}
}

func TestAuthorizeRefusesASubjectThatIsNobody(t *testing.T) {
	t.Parallel()

	if _, err := security.Authorize(context.Background(), webhook.EndpointPolicy{}, security.Subject{}, webhook.EndpointView, webhook.Endpoint{}); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("an empty subject was authorized: %v", err)
	}
}

// nilHandle is a handle over no database. Any statement issued through it
// panics.
func nilHandle() *data.DB { return data.Wrap(nil, data.DialectSQLite) }

func TestTheServicesRefuseBeforeReachingTheModel(t *testing.T) {
	t.Parallel()

	module, err := webhook.New(webhook.Config{Key: []byte(testKey)}, nilHandle(), nil)
	if err != nil {
		t.Fatal(err)
	}
	endpoints, calls := module.EndpointService(), module.CallService()
	ctx, who := context.Background(), administrator()

	for name, call := range map[string]func() error{
		"Endpoint.List":      func() error { _, err := endpoints.List(ctx, who, data.Query{}); return err },
		"Endpoint.Find":      func() error { _, err := endpoints.Find(ctx, who, "e-1"); return err },
		"Endpoint.Update":    func() error { _, err := endpoints.Update(ctx, who, "e-1", validRequest()); return err },
		"Endpoint.Delete":    func() error { return endpoints.Delete(ctx, who, "e-1") },
		"Endpoint.Secret":    func() error { _, err := endpoints.Secret(ctx, who, "e-1"); return err },
		"Endpoint.Headers":   func() error { _, err := endpoints.HeaderNames(ctx, who, "e-1"); return err },
		"Endpoint.Test":      func() error { _, err := endpoints.Test(ctx, who, "e-1"); return err },
		"Endpoint.Rotate":    func() error { _, err := endpoints.Rotate(ctx, who, "e-1", time.Hour); return err },
		"Endpoint.Enable":    func() error { _, err := endpoints.Enable(ctx, who, "e-1"); return err },
		"Endpoint.Disable":   func() error { _, err := endpoints.Disable(ctx, who, "e-1"); return err },
		"Endpoint.Delivery":  func() error { _, err := endpoints.Delivery(ctx, who, "d-1"); return err },
		"Endpoint.Attempts":  func() error { _, err := endpoints.Attempts(ctx, who, "d-1"); return err },
		"Endpoint.Redeliver": func() error { _, err := endpoints.Redeliver(ctx, who, "d-1"); return err },
		"Endpoint.Import": func() error {
			_, err := endpoints.Import(ctx, who, webhook.ImportRequest{ID: "e-1", EndpointRequest: validRequest(), Secret: testKey})
			return err
		},
		"Endpoint.Deliveries": func() error { _, err := endpoints.Deliveries(ctx, who, "e-1", 10); return err },
		"Endpoint.Create":     func() error { _, _, err := endpoints.Create(ctx, who, validRequest()); return err },
		"Call.List":           func() error { _, err := calls.List(ctx, who, webhook.CallFilter{}, data.Query{}); return err },
		"Call.Find":           func() error { _, err := calls.Find(ctx, who, "c-1"); return err },
		"Call.Process":        func() error { return calls.Process(ctx, who, "c-1") },
	} {
		if err := call(); !errors.Is(err, security.ErrForbidden) {
			t.Fatalf("%s reached the Model before the policy refusal: %v", name, err)
		}
	}
}

func validRequest() webhook.EndpointRequest {
	return webhook.EndpointRequest{Name: "Billing", URL: "https://example.com/hooks", Events: []string{"order.paid"}, Active: true}
}

// recordingHandle runs nothing and keeps every statement it is handed, so a
// test reads what a table compiles instead of reading its settings.
type recordingHandle struct {
	*data.DB
	statements []recordedStatement
}

type recordedStatement struct {
	sql      string
	bindings []any
}

func newRecordingHandle() *recordingHandle { return &recordingHandle{DB: nilHandle()} }

func (h *recordingHandle) record(sql string, bindings []any) {
	h.statements = append(h.statements, recordedStatement{sql: sql, bindings: slices.Clone(bindings)})
}

func (h *recordingHandle) Select(_ context.Context, sql string, bindings []any, _ bool) ([]query.Record, error) {
	h.record(sql, bindings)
	return nil, nil
}

func (h *recordingHandle) Insert(_ context.Context, sql string, bindings []any) (bool, error) {
	h.record(sql, bindings)
	return true, nil
}

func (h *recordingHandle) Update(_ context.Context, sql string, bindings []any) (int64, error) {
	h.record(sql, bindings)
	return 1, nil
}

func (h *recordingHandle) Delete(_ context.Context, sql string, bindings []any) (int64, error) {
	h.record(sql, bindings)
	return 1, nil
}

func (h *recordingHandle) Statement(_ context.Context, sql string, bindings []any) (bool, error) {
	h.record(sql, bindings)
	return true, nil
}

func (h *recordingHandle) first(t *testing.T, verb string) recordedStatement {
	t.Helper()
	for _, statement := range h.statements {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(statement.sql)), verb) {
			return statement
		}
	}
	t.Fatalf("no %s statement was issued; recorded %v", verb, h.statements)
	return recordedStatement{}
}

// TestTheTablesAreWiredAndTenantScoped holds what each table declares,
// through what it makes the generated query do: the table it reads, a key the
// application writes, and a tenant_id taken from the Grant on the way in and
// on the way out.
func TestTheTablesAreWiredAndTenantScoped(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	write := security.SystemGrant(webhook.CallReceive, "acme")

	endpointHandle := newRecordingHandle()
	if name := webhook.Endpoints(endpointHandle).Base().Table().Name(); name != "webhook_server_endpoints" {
		t.Fatalf("Endpoints reads %q", name)
	}
	endpoint, err := webhook.Endpoints(endpointHandle).New()
	if err != nil {
		t.Fatal(err)
	}
	endpoint.ID = "e-1"
	if _, err := endpoint.Save(ctx, write); err != nil {
		t.Fatal(err)
	}
	insert := endpointHandle.first(t, "insert")
	if !slices.Contains(insert.bindings, any("e-1")) || !strings.Contains(insert.sql, "tenant_id") || !slices.Contains(insert.bindings, any("acme")) {
		t.Fatalf("the endpoint insert %q %v does not write the application key and the Grant's tenant", insert.sql, insert.bindings)
	}

	callHandle := newRecordingHandle()
	if name := webhook.Calls(callHandle).Base().Table().Name(); name != "webhook_client_calls" {
		t.Fatalf("Calls reads %q", name)
	}
	if _, err := webhook.Calls(callHandle).WhereKey("c-1").First(ctx, write); err != nil {
		t.Fatal(err)
	}
	read := callHandle.first(t, "select")
	if !strings.Contains(read.sql, "tenant_id") || !slices.Contains(read.bindings, any("acme")) {
		t.Fatalf("the call read %q %v is not filtered by the Grant's tenant", read.sql, read.bindings)
	}

	deliveryHandle := newRecordingHandle()
	if name := webhook.Deliveries(deliveryHandle).Base().Table().Name(); name != "webhook_server_deliveries" {
		t.Fatalf("Deliveries reads %q", name)
	}
	if _, err := webhook.Deliveries(deliveryHandle).Get(ctx, write); err != nil {
		t.Fatal(err)
	}
	read = deliveryHandle.first(t, "select")
	if !strings.Contains(read.sql, "tenant_id") || !slices.Contains(read.bindings, any("acme")) {
		t.Fatalf("the delivery read %q %v is not filtered by the Grant's tenant", read.sql, read.bindings)
	}

	attemptHandle := newRecordingHandle()
	if name := webhook.DeliveryAttempts(attemptHandle).Base().Table().Name(); name != "webhook_server_delivery_attempts" {
		t.Fatalf("DeliveryAttempts reads %q", name)
	}
	if _, err := webhook.DeliveryAttempts(attemptHandle).Get(ctx, write); err != nil {
		t.Fatal(err)
	}
	read = attemptHandle.first(t, "select")
	if !strings.Contains(read.sql, "tenant_id") || !slices.Contains(read.bindings, any("acme")) {
		t.Fatalf("the attempt read %q %v is not filtered by the Grant's tenant", read.sql, read.bindings)
	}
}

func TestTheMissingRecordIsTheModelsNotFound(t *testing.T) {
	t.Parallel()

	if !errors.Is(webhook.ErrNotFound, model.ErrModelNotFound) {
		t.Fatal("ErrNotFound does not wrap model.ErrModelNotFound, so the router would answer a missing record with 500")
	}
}

func TestASystemGrantWithoutATenantReachesNothing(t *testing.T) {
	t.Parallel()

	_, err := webhook.Calls(nilHandle()).WhereKey("c-1").First(context.Background(), security.SystemGrant(webhook.CallReceive, ""))
	if !errors.Is(err, model.ErrNoTenant) {
		t.Fatalf("a system grant with no tenant returned %v, want ErrNoTenant", err)
	}
}

func TestTheTenantComesFromTheGrant(t *testing.T) {
	t.Parallel()

	if got := data.Tenant(security.SystemGrant(webhook.CallReceive, "acme")); got != "acme" {
		t.Fatalf("data.Tenant(g) = %q, want acme", got)
	}
	if got := data.Tenant(security.Grant{}); got != "" {
		t.Fatalf("the zero Grant carries the tenant %q, want none", got)
	}
}

func TestTheConfigurationRefusesWhatCannotWork(t *testing.T) {
	t.Parallel()

	key := []byte(testKey)
	process := webhook.ProcessorFunc(func(context.Context, security.Grant, *webhook.Call) error { return nil })
	resolver := webhook.ResolverFunc(func(*http.Request) (webhook.Resolution, error) { return webhook.Resolution{}, nil })
	receiver := func(r webhook.Receiver) webhook.Config {
		if r.Process == nil {
			r.Process = process
		}
		return webhook.Config{Key: key, Receivers: []webhook.Receiver{r}}
	}
	for name, cfg := range map[string]webhook.Config{
		"no key":                                  {},
		"short key":                               {Key: []byte("short")},
		"relative prefix":                         {Key: key, Prefix: "webhook"},
		"prefix ending in a slash":                {Key: key, ReceivePrefix: "/webhooks/"},
		"page size too big":                       {Key: key, PageSize: webhook.MaxPageSize + 1},
		"short named secret":                      {Key: key, Server: webhook.Server{Secrets: map[string]string{"partners": "short"}}},
		"bad named secret":                        {Key: key, Server: webhook.Server{Secrets: map[string]string{"Partners!": testKey}}},
		"bad header prefix":                       {Key: key, Server: webhook.Server{HeaderPrefix: "X Acme"}},
		"policy without tries":                    {Key: key, Server: webhook.Server{Policy: &webhook.Policy{Timeout: time.Second, MaxRequestBytes: 1}}},
		"policy beside a timeout":                 {Key: key, Server: webhook.Server{Policy: policyWith(func(p *webhook.Policy) {}), Timeout: time.Second}},
		"policy with no wait":                     {Key: key, Server: webhook.Server{Policy: policyWith(func(p *webhook.Policy) { p.Backoff = nil })}},
		"policy with a long wait":                 {Key: key, Server: webhook.Server{Policy: policyWith(func(p *webhook.Policy) { p.Backoff = []time.Duration{webhook.MaxBackoff + 1} })}},
		"policy with no timeout":                  {Key: key, Server: webhook.Server{Policy: policyWith(func(p *webhook.Policy) { p.Timeout = 0 })}},
		"policy with a huge body":                 {Key: key, Server: webhook.Server{Policy: policyWith(func(p *webhook.Policy) { p.MaxRequestBytes = webhook.MaxRequestBytes + 1 })}},
		"policy with a bad retry":                 {Key: key, Server: webhook.Server{Policy: policyWith(func(p *webhook.Policy) { p.Retry = "sometimes" })}},
		"policy with a bad agent":                 {Key: key, Server: webhook.Server{Policy: policyWith(func(p *webhook.Policy) { p.UserAgent = "a\nb" })}},
		"receiver without a name":                 receiver(webhook.Receiver{Tenant: "acme", Secret: testKey}),
		"receiver without a tenant":               receiver(webhook.Receiver{Name: "billing", Secret: testKey}),
		"receiver without a secret":               receiver(webhook.Receiver{Name: "billing", Tenant: "acme"}),
		"receiver with a bad method":              receiver(webhook.Receiver{Name: "billing", Tenant: "acme", Secret: testKey, Methods: []string{"TRACE"}}),
		"receiver without a process":              {Key: key, Receivers: []webhook.Receiver{{Name: "billing", Tenant: "acme", Secret: testKey}}},
		"a receiver with a tenant and a resolver": receiver(webhook.Receiver{Name: "lpr", Tenant: "acme", Resolve: resolver}),
		"a receiver with a path and a mount":      receiver(webhook.Receiver{Name: "lpr", Resolve: resolver, Path: "lpr/{key}", Mount: "/lpr/{key}"}),
		"a path that starts with a slash":         receiver(webhook.Receiver{Name: "lpr", Resolve: resolver, Path: "/lpr/{key}"}),
		"a mount that is relative":                receiver(webhook.Receiver{Name: "lpr", Resolve: resolver, Mount: "lpr/{key}"}),
		"a mount in the framework's namespace":    receiver(webhook.Receiver{Name: "lpr", Resolve: resolver, Mount: "/_arandu/lpr"}),
		"a path that is not a pattern":            receiver(webhook.Receiver{Name: "lpr", Resolve: resolver, Path: "lpr/{key"}),
		"a refusal that is not one":               receiver(webhook.Receiver{Name: "lpr", Resolve: resolver, Statuses: webhook.Statuses{Unresolved: 200}}),
		"both processors": receiver(webhook.Receiver{Name: "lpr", Resolve: resolver,
			ProcessSync: webhook.SyncProcessorFunc(func(context.Context, security.Grant, *webhook.Call) (webhook.ProcessResult, error) {
				return webhook.ProcessResult{}, nil
			})}),
		"two receivers at one address": {Key: key, Receivers: []webhook.Receiver{
			{Name: "first", Tenant: "acme", Secret: testKey, Process: process, Path: "shared"},
			{Name: "second", Tenant: "acme", Secret: testKey, Process: process, Mount: "/webhooks/shared"},
		}},
		"a receiver twice": {Key: key, Receivers: []webhook.Receiver{
			{Name: "billing", Tenant: "acme", Secret: testKey, Process: process},
			{Name: "billing", Tenant: "acme", Secret: testKey, Process: process},
		}},
	} {
		if err := cfg.Validate(); err == nil {
			t.Errorf("the configuration with %s was accepted", name)
		}
	}

	if err := (webhook.Config{Key: key}).Validate(); err != nil {
		t.Fatalf("the smallest configuration was refused: %v", err)
	}
	if err := (webhook.Config{Key: key, Server: webhook.Server{Policy: policyWith(func(*webhook.Policy) {})}}).Validate(); err != nil {
		t.Fatalf("the default policy, written out, was refused: %v", err)
	}
}

// policyWith is the default policy with one change.
func policyWith(change func(*webhook.Policy)) *webhook.Policy {
	p := webhook.DefaultPolicy()
	change(&p)
	return &p
}

func TestTheDefaultPolicyIsTheOneV010Delivered(t *testing.T) {
	t.Parallel()

	p := webhook.DefaultPolicy()
	if p.Tries != 5 || !slices.Equal(p.Backoff, []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}) ||
		!p.HonorRetryAfter || p.Retry != webhook.RetryTransient || p.HTTPSOnly || p.MaxRedirects != 5 ||
		p.Timeout != webhook.DefaultTimeout || p.UserAgent != webhook.DefaultUserAgent || p.DisableAfter != 0 {
		t.Fatalf("the default policy is %+v", p)
	}
}
