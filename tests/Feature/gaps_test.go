package feature_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arandu-io/framework/foundation"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/framework/validation"
	"github.com/arandu-io/hesape/events"

	webhook "github.com/hyz-is/arandu-webhook"
)

func TestAnImportKeepsTheEndpointsHistory(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	w := strictWorld(t, tg, clk, nil)
	ctx := context.Background()
	created := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	disabled := time.Date(2025, 6, 2, 8, 30, 0, 0, time.UTC)

	_, err := w.module.EndpointService().Import(ctx, importer(tenant), webhook.ImportRequest{
		ID: "ep_old",
		EndpointRequest: webhook.EndpointRequest{
			Name: "Merchant", URL: tg.baseURL + "/hooks", Events: []string{"*"}, Dialect: webhook.DialectStandardWebhooks,
		},
		Secret: stdSecret, CreatedAt: created,
		ConsecutiveFailures: 20, DisabledAt: &disabled, DisabledReason: webhook.DisabledByFailures,
	})
	if err != nil {
		t.Fatal(err)
	}
	row := w.endpoint(t, "ep_old")
	if !row.CreatedAt.Equal(created) || row.ConsecutiveFailures != 20 || row.DisabledAt == nil || !row.DisabledAt.Equal(disabled) ||
		row.DisabledReason != webhook.DisabledByFailures || bool(row.Active) {
		t.Fatalf("the imported endpoint is %+v", row)
	}

	for name, in := range map[string]webhook.ImportRequest{
		"a negative count":          {ConsecutiveFailures: -1},
		"a reason with no date":     {DisabledReason: "paused by the merchant"},
		"a date with no reason":     {DisabledAt: &disabled},
		"turned off and active":     {DisabledAt: &disabled, DisabledReason: "paused", EndpointRequest: webhook.EndpointRequest{Active: true}},
		"a reason of two lines":     {DisabledAt: &disabled, DisabledReason: "paused\nby us"},
		"a reason that is too long": {DisabledAt: &disabled, DisabledReason: strings.Repeat("x", webhook.MaxDisabledReason+1)},
	} {
		in.ID, in.Secret = "ep_bad", stdSecret
		in.Name, in.URL, in.Events, in.Dialect = "Bad", tg.baseURL+"/hooks", []string{"*"}, webhook.DialectStandardWebhooks
		if _, err := w.module.EndpointService().Import(ctx, importer(tenant), in); !errors.As(err, new(validation.Errors)) {
			t.Errorf("an import with %s answered %v", name, err)
		}
	}
}

func TestAnEndpointIsTurnedOffWithTheReasonGiven(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	w := strictWorld(t, tg, clk, nil)
	ctx := context.Background()
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret)

	if _, err := w.module.EndpointService().DisableWithReason(ctx, manager(tenant), "ep_merchant_1", "line one\nline two"); !errors.As(err, new(validation.Errors)) {
		t.Fatalf("a reason of two lines answered %v", err)
	}
	record, err := w.module.EndpointService().DisableWithReason(ctx, manager(tenant), "ep_merchant_1", "maintenance window")
	if err != nil {
		t.Fatal(err)
	}
	row := w.endpoint(t, "ep_merchant_1")
	if bool(record.Active) || bool(row.Active) || row.DisabledReason != "maintenance window" || row.DisabledAt == nil {
		t.Fatalf("the endpoint turned off with a reason is %+v", row)
	}
	var payload map[string]any
	rows := outboxRows(t, w)
	last := rows[len(rows)-1]
	if err := json.Unmarshal([]byte(last.Payload), &payload); err != nil || last.Name != webhook.EventEndpointDisabled || payload["reason"] != "maintenance window" {
		t.Fatalf("the event recorded is %s %s", last.Name, last.Payload)
	}

	// Through the route, the reason travels in the form.
	if _, err := w.module.EndpointService().Enable(ctx, manager(tenant), "ep_merchant_1"); err != nil {
		t.Fatal(err)
	}
	cookies := w.signIn(t, manager(tenant))
	if rec := w.as(t, cookies, http.MethodPost, "/webhook/endpoints/ep_merchant_1/disable", `{"reason":"merchant asked"}`); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"disabled_reason":"merchant asked"`) {
		t.Fatalf("the disable route answered %d %s", rec.Code, rec.Body.String())
	}
	if n := len(outboxRows(t, w)); n != len(rows)+2 {
		t.Fatalf("turning on and off again recorded %d events, want 2", n-len(rows))
	}
}

func TestAnEmptySubscriptionIsOptIn(t *testing.T) {
	t.Parallel()
	tg := newTarget(t, false)
	ctx := context.Background()
	empty := webhook.EndpointRequest{Name: "Quiet", URL: tg.baseURL + "/hooks", Active: true}

	closed := install(t, func(c *webhook.Config, _ *handled) { c.Server.HTTPClient = tg.srv.Client() })
	if _, _, err := closed.module.EndpointService().Create(ctx, manager(tenant), empty); !errors.As(err, new(validation.Errors)) {
		t.Fatalf("an endpoint with no event was accepted by default: %v", err)
	}

	w := install(t, func(c *webhook.Config, _ *handled) {
		c.Server.HTTPClient = tg.srv.Client()
		c.Server.AllowEmptySubscription = true
	})
	endpoint, _, err := w.module.EndpointService().Create(ctx, manager(tenant), empty)
	if err != nil {
		t.Fatalf("an endpoint with no event was refused with AllowEmptySubscription: %v", err)
	}
	if err := w.module.Publisher().Publish(ctx, events.Stored{ID: "evt-1", TenantID: tenant, Name: "order.paid", Payload: `{}`}); err != nil {
		t.Fatal(err)
	}
	if w.pending(t) != 0 {
		t.Fatal("an endpoint subscribed to nothing was sent an event")
	}
	if _, err := w.module.Send(ctx, dispatch(tenant), endpoint.ID, webhook.Message{Event: "order.paid", Body: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	if len(tg.requests()) != 1 {
		t.Fatalf("a message sent to an endpoint subscribed to nothing took %d requests", len(tg.requests()))
	}
}

// inspecting is a synchronous processor that keeps what it saw.
type inspecting struct {
	mu       sync.Mutex
	received http.Header
	call     webhook.Call
}

func (p *inspecting) ProcessNow(_ context.Context, _ security.Grant, call *webhook.Call) (webhook.ProcessResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.received = call.ReceivedHeaders()
	p.call = webhook.Call{RemoteAddr: call.RemoteAddr, HeadersSHA256: call.HeadersSHA256, URL: call.URL}
	return webhook.ProcessResult{}, nil
}

func TestAProcessorSeesWhoCalledAndEveryHeader(t *testing.T) {
	t.Parallel()
	seen := &inspecting{}
	w := install(t, func(c *webhook.Config, h *handled) {
		c.Receivers = []webhook.Receiver{
			{Name: "cielo", Path: "cielo/{token}", Resolve: cieloResolver, Validator: webhook.HeaderSecret{Header: "X-Perata-Notification"}, ProcessSync: seen},
			{Name: "billing", Tenant: tenant, Secret: sharedSecret, StoreHeaders: []string{"X-Request-Id"}},
		}
	})
	req := notification("/webhooks/cielo/"+token("acme", "ep-1")+"?source=gateway", `{"PaymentId":"p-1"}`, cieloSecret)
	req.RemoteAddr = "203.0.113.7:51234"
	req.Header.Set("X-Trace", "abc")
	if rec := w.send(t, req); rec.Code != http.StatusOK {
		t.Fatalf("the notification answered %d", rec.Code)
	}
	if seen.received.Get("X-Perata-Notification") != cieloSecret || seen.received.Get("X-Trace") != "abc" {
		t.Fatalf("the processor saw the headers %v", seen.received)
	}
	if seen.call.RemoteAddr != "203.0.113.7:51234" || seen.call.HeadersSHA256 != webhook.HeadersDigest(req.Header) {
		t.Fatalf("the processor saw %+v", seen.call)
	}
	stored := w.calls(t, "acme")[0]
	if stored.RemoteAddr != "203.0.113.7:51234" || stored.HeadersSHA256 != webhook.HeadersDigest(req.Header) || stored.Header("X-Perata-Notification") != "" {
		t.Fatalf("the call was stored as %+v", stored)
	}
	if stored.ReceivedHeaders() != nil {
		t.Fatal("a call read back from its table still carries the request's headers")
	}

	// A queued processor reads the call back: the kept headers and the
	// digest, not the request's headers.
	queued := signed("/webhooks/billing", `{"a":1}`, sharedSecret)
	queued.RemoteAddr = "198.51.100.2:443"
	w.send(t, queued)
	if err := w.work(t); err != nil {
		t.Fatal(err)
	}
	got := w.handled.seen()
	if len(got) != 1 || got[0].RemoteAddr != "198.51.100.2:443" || got[0].HeadersSHA256 == "" || got[0].ReceivedHeaders() != nil || got[0].Header("X-Request-Id") != "req-1" {
		t.Fatalf("the queued processor saw %+v", got)
	}
}

func TestAPathTokenIsNotKeptWithTheCall(t *testing.T) {
	t.Parallel()
	w := install(t, func(c *webhook.Config, _ *handled) {
		c.Receivers = []webhook.Receiver{
			{Name: "cielo", Path: "cielo/{token}", Resolve: cieloResolver, Validator: webhook.HeaderSecret{Header: "X-Perata-Notification"}, ProcessSync: &filing{}},
			{Name: "cielo-full", Path: "full/{token}", Resolve: cieloResolver, Validator: webhook.HeaderSecret{Header: "X-Perata-Notification"}, ProcessSync: &filing{}, URL: webhook.URLFull},
			{Name: "cielo-none", Path: "none/{token}", Resolve: cieloResolver, Validator: webhook.HeaderSecret{Header: "X-Perata-Notification"}, ProcessSync: &filing{}, URL: webhook.URLNone},
		}
	})
	secretToken := token("acme", "ep-1")
	for _, prefix := range []string{"cielo", "full", "none"} {
		if rec := w.send(t, notification("/webhooks/"+prefix+"/"+secretToken+"?sig=query-secret", `{"a":"`+prefix+`"}`, cieloSecret)); rec.Code != http.StatusOK {
			t.Fatalf("%s answered %d", prefix, rec.Code)
		}
	}
	urls := map[string]string{}
	for _, call := range w.calls(t, "acme") {
		urls[call.Name] = call.URL
	}
	if urls["cielo"] != "http://example.com/webhooks/cielo/{token}" {
		t.Errorf("a receiver with a path parameter kept %q", urls["cielo"])
	}
	if !strings.Contains(urls["cielo-full"], secretToken) {
		t.Errorf("URLFull kept %q", urls["cielo-full"])
	}
	if urls["cielo-none"] != "" {
		t.Errorf("URLNone kept %q", urls["cielo-none"])
	}
	cookies := w.signIn(t, manager("acme"))
	rec := w.as(t, cookies, http.MethodGet, "/webhook/calls?name=cielo", "")
	if strings.Contains(rec.Body.String(), secretToken) || strings.Contains(rec.Body.String(), "query-secret") {
		t.Fatalf("the listing answered the token: %s", rec.Body.String())
	}
}

func TestTheCleansReachEveryTenantWithRows(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	w := strictWorld(t, tg, clk, func(c *webhook.Config) {
		c.Receivers = []webhook.Receiver{
			{Name: "cielo-master", Path: "cielo/master/{environment}", Tenant: "platform", Secret: cieloSecret,
				Validator: webhook.HeaderSecret{Header: "X-Perata-Notification"}, ProcessSync: &filing{}},
			{Name: "cielo", Path: "cielo/{token}", Resolve: cieloResolver, Validator: webhook.HeaderSecret{Header: "X-Perata-Notification"}, ProcessSync: &filing{}},
		}
	})
	ctx := context.Background()
	w.send(t, notification("/webhooks/cielo/master/live", `{"old":true}`, cieloSecret))
	w.send(t, notification("/webhooks/cielo/"+token("globex", "ep-9"), `{"old":true}`, cieloSecret))
	for _, tenantID := range []string{"platform", "globex"} {
		old := w.calls(t, tenantID)[0]
		old.CreatedAt = time.Now().UTC().AddDate(0, 0, -webhook.DefaultDeleteAfterDays-1)
		if _, err := old.Save(ctx, security.SystemGrant(webhook.CallReceive, tenantID)); err != nil {
			t.Fatal(err)
		}
	}
	w.send(t, notification("/webhooks/cielo/master/live", `{"old":false}`, cieloSecret))

	// An old settled delivery of a tenant no scheduler lists either.
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret)
	if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{ID: "msg_old", Event: "e", Body: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	clk.Advance(webhook.DefaultRetention + time.Hour)

	for _, task := range w.module.Schedule() {
		if task.Scope != foundation.Global {
			t.Fatalf("%s is not one pass over every tenant", task.ID)
		}
		if err := task.Run(ctx, security.Grant{}); err != nil {
			t.Fatalf("%s: %v", task.ID, err)
		}
	}
	if left := w.calls(t, "platform"); len(left) != 1 || left[0].Payload != `{"old":false}` {
		t.Fatalf("the platform tenant kept %d calls", len(left))
	}
	if left := w.calls(t, "globex"); len(left) != 0 {
		t.Fatalf("a resolved tenant kept %d old calls", len(left))
	}
	if row, err := webhook.Deliveries(w.db).WhereKey("msg_old").First(ctx, dispatch(tenant)); err != nil || row != nil {
		t.Fatalf("the old delivery is still there: %v %v", row, err)
	}
}
