package feature_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/events"
	hwebhook "github.com/arandu-io/hesape/webhook"

	webhook "github.com/hyz-is/arandu-webhook"
)

// received is a request a test server took.
type received struct {
	header http.Header
	body   string
}

// receiver is a test server that keeps what it is sent.
type receiver struct {
	mu   sync.Mutex
	got  []received
	srv  *httptest.Server
	code int
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{code: http.StatusOK}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, received{header: req.Header.Clone(), body: string(body)})
		code := r.code
		r.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) requests() []received {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]received(nil), r.got...)
}

// sendingWorld is a world whose deliveries go out on the test server's
// client, which reaches loopback, with the headers branded X-Acme.
func sendingWorld(t *testing.T, target *receiver, configure func(*webhook.Config, *handled)) *world {
	t.Helper()
	return install(t, func(c *webhook.Config, h *handled) {
		c.Server.HTTPClient = target.srv.Client()
		c.Server.HeaderPrefix = "X-Acme"
		c.Server.Events = []string{"order.paid", "order.refunded"}
		if configure != nil {
			configure(c, h)
		}
	})
}

type endpointAnswer struct {
	Data struct {
		ID          string   `json:"id"`
		Secret      string   `json:"secret"`
		Events      []string `json:"events"`
		Signer      string   `json:"signer"`
		HeaderNames []string `json:"header_names"`
	} `json:"data"`
}

func createEndpoint(t *testing.T, w *world, cookies []*http.Cookie, body string) endpointAnswer {
	t.Helper()
	rec := w.as(t, cookies, http.MethodPost, "/webhook/endpoints", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating an endpoint answered %d %s", rec.Code, rec.Body.String())
	}
	var out endpointAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("the created endpoint is not JSON: %v %s", err, rec.Body.String())
	}
	return out
}

func TestAnEventIsDeliveredSignedToTheEndpointsSubscribedToIt(t *testing.T) {
	t.Parallel()
	target := newReceiver(t)
	w := sendingWorld(t, target, nil)
	cookies := w.signIn(t, manager(tenant))

	paid := createEndpoint(t, w, cookies, `{"name":"Billing","url":"`+target.srv.URL+`/hooks","events":["order.paid"],"active":true,"headers":"X-Team: billing"}`)
	if paid.Data.Secret == "" || !strings.HasPrefix(paid.Data.Secret, "whsec_") || paid.Data.Signer != webhook.SignerArandu {
		t.Fatalf("the created endpoint answered %+v", paid.Data)
	}
	createEndpoint(t, w, cookies, `{"name":"Refunds","url":"`+target.srv.URL+`/refunds","events":["order.refunded"],"active":true}`)
	createEndpoint(t, w, cookies, `{"name":"Paused","url":"`+target.srv.URL+`/paused","events":["*"],"active":false}`)

	payload := `{"order":"o-1","total":4700}`
	stored := events.Stored{ID: "evt-1", TenantID: tenant, Name: "order.paid", Payload: payload, OccurredAt: time.Now().UTC()}
	if err := w.module.Publisher().Publish(context.Background(), stored); err != nil {
		t.Fatalf("publishing: %v", err)
	}
	// The relay publishes an event again after a crash; the delivery is one.
	if err := w.module.Publisher().Publish(context.Background(), stored); err != nil {
		t.Fatalf("publishing again: %v", err)
	}
	if n := w.pending(t); n != 1 {
		t.Fatalf("%d deliveries wait, want the one endpoint subscribed to order.paid", n)
	}
	if err := w.work(t); err != nil {
		t.Fatalf("delivering: %v", err)
	}

	got := target.requests()
	if len(got) != 1 {
		t.Fatalf("the receiver took %d requests", len(got))
	}
	r := got[0]
	if r.body != payload || r.header.Get("X-Team") != "billing" {
		t.Fatalf("the delivery carried %q and X-Team %q", r.body, r.header.Get("X-Team"))
	}
	if r.header.Get("X-Arandu-Signature") != "" {
		t.Fatal("the delivery kept the X-Arandu headers, which HeaderPrefix renames")
	}
	if !hwebhook.Verify(hwebhook.SecretSet{Current: []byte(paid.Data.Secret)}, r.header.Get("X-Acme-Timestamp"), r.header.Get("X-Acme-Delivery-Id"), []byte(r.body), r.header.Get("X-Acme-Signature")) {
		t.Fatalf("the delivery's signature does not verify with the endpoint's secret: %v", r.header)
	}

	// The delivery's record is read back through the endpoint.
	rec := w.as(t, cookies, http.MethodGet, "/webhook/endpoints/"+paid.Data.ID+"/deliveries", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"delivered"`) || !strings.Contains(rec.Body.String(), `"response_status":200`) {
		t.Fatalf("the deliveries answered %d %s", rec.Code, rec.Body.String())
	}
}

func TestAnHMACEndpointCarriesTheBodySignature(t *testing.T) {
	t.Parallel()
	target := newReceiver(t)
	w := sendingWorld(t, target, nil)
	cookies := w.signIn(t, manager(tenant))

	legacy := createEndpoint(t, w, cookies, `{"name":"Legacy","url":"`+target.srv.URL+`/legacy","events":["*"],"signer":"hmac","signature_header":"X-Signature-256","active":true}`)
	payload := `{"plate":"BRA2E19"}`
	if err := w.module.Publisher().Publish(context.Background(), events.Stored{ID: "evt-2", TenantID: tenant, Name: "order.refunded", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if err := w.work(t); err != nil {
		t.Fatal(err)
	}
	got := target.requests()
	if len(got) != 1 || got[0].header.Get("X-Signature-256") != webhook.SignBody([]byte(legacy.Data.Secret), []byte(payload)) {
		t.Fatalf("the HMAC endpoint received %v", got)
	}
}

func TestTheTestButtonSendsWhateverTheSubscription(t *testing.T) {
	t.Parallel()
	target := newReceiver(t)
	w := sendingWorld(t, target, nil)
	cookies := w.signIn(t, manager(tenant))
	paused := createEndpoint(t, w, cookies, `{"name":"Paused","url":"`+target.srv.URL+`/p","events":["order.paid"],"active":false}`)

	if rec := w.as(t, cookies, http.MethodPost, "/webhook/endpoints/"+paused.Data.ID+"/test", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("the test answered %d %s", rec.Code, rec.Body.String())
	}
	if err := w.work(t); err != nil {
		t.Fatal(err)
	}
	got := target.requests()
	if len(got) != 1 || !strings.Contains(got[0].body, `"event":"webhook.test"`) {
		t.Fatalf("the test delivered %v", got)
	}
}

func TestTheEndpointsAreManagedWithinTheTenant(t *testing.T) {
	t.Parallel()
	target := newReceiver(t)
	w := sendingWorld(t, target, nil)
	acme := w.signIn(t, manager(tenant))
	globex := w.signIn(t, manager("globex"))

	created := createEndpoint(t, w, acme, `{"name":"Billing","url":"`+target.srv.URL+`/h","events":["order.paid"],"active":true,"headers":"X-Team: billing\nX-Env: prod"}`)
	id := created.Data.ID

	if rec := w.as(t, acme, http.MethodGet, "/webhook/endpoints/"+id+"/secret", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), created.Data.Secret) {
		t.Fatalf("the secret answered %d %s", rec.Code, rec.Body.String())
	}
	// The secret leaves only through its own route.
	if rec := w.as(t, acme, http.MethodGet, "/webhook/endpoints/"+id, ""); strings.Contains(rec.Body.String(), created.Data.Secret) || strings.Contains(rec.Body.String(), "tenant") {
		t.Fatalf("the endpoint answered its secret or its tenant: %s", rec.Body.String())
	}

	// An update with no headers keeps the stored ones.
	rec := w.as(t, acme, http.MethodPut, "/webhook/endpoints/"+id, `{"name":"Billing v2","url":"`+target.srv.URL+`/h2","events":["order.paid","order.refunded"],"active":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("the update answered %d %s", rec.Code, rec.Body.String())
	}
	names, err := w.module.EndpointService().HeaderNames(context.Background(), manager(tenant), id)
	if err != nil || strings.Join(names, ",") != "X-Env,X-Team" {
		t.Fatalf("after an update without headers the endpoint has %v, %v", names, err)
	}

	for _, request := range []struct{ method, target string }{
		{http.MethodGet, "/webhook/endpoints/" + id},
		{http.MethodGet, "/webhook/endpoints/" + id + "/secret"},
		{http.MethodPut, "/webhook/endpoints/" + id},
		{http.MethodDelete, "/webhook/endpoints/" + id},
		{http.MethodPost, "/webhook/endpoints/" + id + "/test"},
	} {
		body := ""
		if request.method == http.MethodPut {
			body = `{"name":"Taken","url":"https://example.com","events":["order.paid"]}`
		}
		if rec := w.as(t, globex, request.method, request.target, body); rec.Code != http.StatusNotFound {
			t.Errorf("another tenant's %s %s answered %d, want 404", request.method, request.target, rec.Code)
		}
	}

	if rec := w.as(t, acme, http.MethodDelete, "/webhook/endpoints/"+id, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("the delete answered %d", rec.Code)
	}
	if rec := w.as(t, acme, http.MethodGet, "/webhook/endpoints/"+id, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("a deleted endpoint answered %d", rec.Code)
	}
}

func TestAnEndpointIsValidated(t *testing.T) {
	t.Parallel()
	target := newReceiver(t)
	w := sendingWorld(t, target, nil)
	cookies := w.signIn(t, manager(tenant))

	for name, body := range map[string]string{
		"no name":               `{"url":"https://example.com","events":["order.paid"]}`,
		"a relative url":        `{"name":"x","url":"/hooks","events":["order.paid"]}`,
		"a url with a password": `{"name":"x","url":"https://u:p@example.com","events":["order.paid"]}`,
		"no event":              `{"name":"x","url":"https://example.com"}`,
		"an event off the list": `{"name":"x","url":"https://example.com","events":["user.deleted"]}`,
		"an unknown signer":     `{"name":"x","url":"https://example.com","events":["order.paid"],"signer":"rsa"}`,
		"a reserved header":     `{"name":"x","url":"https://example.com","events":["order.paid"],"headers":"X-Acme-Signature: forged"}`,
		"a broken header line":  `{"name":"x","url":"https://example.com","events":["order.paid"],"headers":"no colon here"}`,
	} {
		if rec := w.as(t, cookies, http.MethodPost, "/webhook/endpoints", body); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("an endpoint with %s answered %d, want 422", name, rec.Code)
		}
	}
}

func TestAnOutgoingCallReachesAReceiverOfTheSameModule(t *testing.T) {
	t.Parallel()
	// The module sends to its own receivers, through a real server: the two
	// halves agree on both schemes.
	var self *world
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { self.router.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	self = install(t, func(c *webhook.Config, _ *handled) {
		c.Server.HTTPClient = srv.Client()
		c.Server.HeaderPrefix = "X-Acme"
		c.Server.Secrets = map[string]string{"self": sharedSecret}
		c.Receivers = []webhook.Receiver{
			{Name: "arandu", Tenant: tenant, Secret: sharedSecret, Validator: webhook.Arandu{HeaderPrefix: "X-Acme"}},
			{Name: "spatie", Tenant: tenant, Secret: sharedSecret, Validator: webhook.HMAC{Header: "X-Signature-256"}},
		}
	})
	g := security.SystemGrant(hwebhook.ActionDispatch, tenant)

	if err := self.module.Outgoing().URL(srv.URL+"/webhooks/arandu").Event("order.paid").Payload(map[string]any{"order": "o-9"}).UseSecret("self").Dispatch(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if err := self.module.Outgoing().URL(srv.URL+"/webhooks/spatie").Payload(map[string]any{"order": "o-10"}).UseSecret("self").SignWithHMAC("X-Signature-256").Dispatch(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6 && len(self.handled.seen()) < 2; i++ {
		if err := self.work(t); err != nil {
			t.Fatalf("working: %v", err)
		}
	}
	seen := self.handled.seen()
	if len(seen) != 2 {
		t.Fatalf("the receivers processed %d calls, want 2", len(seen))
	}
	names := seen[0].Name + "," + seen[1].Name
	if names != "arandu,spatie" && names != "spatie,arandu" {
		t.Fatalf("the calls arrived at %s", names)
	}
}

func TestAnOutgoingCallRefusesWhatCannotBeSent(t *testing.T) {
	t.Parallel()
	target := newReceiver(t)
	w := sendingWorld(t, target, func(c *webhook.Config, _ *handled) {
		c.Server.Secrets = map[string]string{"partners": sharedSecret}
	})
	g := security.SystemGrant(hwebhook.ActionDispatch, tenant)
	ctx := context.Background()

	if err := w.module.Outgoing().UseSecret("partners").Dispatch(ctx, g); err != webhook.ErrURLNotSet {
		t.Errorf("a call with no URL answered %v", err)
	}
	if err := w.module.Outgoing().URL(target.srv.URL).Dispatch(ctx, g); err != webhook.ErrSecretNotSet {
		t.Errorf("a call with no secret answered %v", err)
	}
	if err := w.module.Outgoing().URL(target.srv.URL).UseSecret("nobody").Dispatch(ctx, g); err != webhook.ErrUnknownSecret {
		t.Errorf("a call with an unknown secret answered %v", err)
	}
	if err := w.module.Outgoing().URL(target.srv.URL).UseSecret("partners").WithHeaders(map[string]string{"User-Agent": "x"}).Dispatch(ctx, g); err == nil {
		t.Error("a call that sets User-Agent was accepted")
	}
	if err := w.module.Outgoing().URL(target.srv.URL).UseSecret("partners").DispatchIf(ctx, false, g); err != nil || w.pending(t) != 0 {
		t.Errorf("DispatchIf(false) dispatched: %v, %d jobs", err, w.pending(t))
	}
	// A Grant that is not hesape's dispatch is refused by the Manager.
	if err := w.module.Outgoing().URL(target.srv.URL).UseSecret("partners").Dispatch(ctx, security.SystemGrant(webhook.CallReceive, tenant)); err == nil {
		t.Error("a call dispatched under another action was accepted")
	}
}
