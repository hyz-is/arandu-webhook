package feature_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arandu-io/framework/security"
	hwebhook "github.com/arandu-io/hesape/webhook"

	webhook "github.com/hyz-is/arandu-webhook"
)

// inbound is a record of the application that takes calls: what a dynamic
// receiver resolves a request to.
type inbound struct {
	tenant, id, org string
	secret          string
	previous        []string
	active          bool
}

// tokenKey signs the tokens in the path, as an application's signer would.
const tokenKey = "token-key-token-key-token-key-012"

// token is the path segment that names a record: its tenant and id, and a
// signature over both that only the application can make.
func token(tenantID, id string) string {
	mac := hmac.New(sha256.New, []byte(tokenKey))
	mac.Write([]byte(tenantID + "." + id))
	return tenantID + "." + id + "." + hex.EncodeToString(mac.Sum(nil))
}

// cieloSecret is the environment's notification secret, sent as it is.
const cieloSecret = "cielo-notification-secret-0123456"

// records are the application's inbound records, by tenant and id.
var records = map[string]inbound{
	"acme/ep-1":   {tenant: "acme", id: "ep-1", active: true},
	"acme/ep-off": {tenant: "acme", id: "ep-off", active: false},
	"globex/ep-9": {tenant: "globex", id: "ep-9", active: true},
}

// cieloResolver reads the token, checks its signature, and finds the record
// under the tenant the token names. Nothing else of the request is read.
var cieloResolver = webhook.ResolverFunc(func(r *http.Request) (webhook.Resolution, error) {
	parts := strings.Split(r.PathValue("token"), ".")
	if len(parts) != 3 {
		return webhook.Resolution{}, errors.New("not a token")
	}
	if parts[0] == "down" {
		return webhook.Resolution{}, fmt.Errorf("the inbox: %w", webhook.ErrReceiverUnavailable)
	}
	if !hmac.Equal([]byte(token(parts[0], parts[1])), []byte(r.PathValue("token"))) {
		return webhook.Resolution{}, errors.New("the token was not signed here")
	}
	record, ok := records[parts[0]+"/"+parts[1]]
	if !ok || !record.active {
		return webhook.Resolution{}, errors.New("no such inbound endpoint")
	}
	return webhook.Resolution{Tenant: record.tenant, Secret: cieloSecret, Reference: record.id}, nil
})

// filing is a synchronous processor that files a notification once, by its
// body, and answers 200 to the first and to a replay alike.
type filing struct {
	mu    sync.Mutex
	seen  map[string]bool
	fail  error
	calls []*webhook.Call
}

func (f *filing) ProcessNow(_ context.Context, g security.Grant, call *webhook.Call) (webhook.ProcessResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return webhook.ProcessResult{}, f.fail
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	f.calls = append(f.calls, call)
	f.seen[call.TenantID+"/"+call.Payload] = true
	return webhook.ProcessResult{Status: http.StatusOK}, nil
}

func cieloWorld(t *testing.T, f *filing) *world {
	t.Helper()
	return install(t, func(c *webhook.Config, _ *handled) {
		c.Receivers = []webhook.Receiver{{
			Name: "cielo", Path: "cielo/{token}", Resolve: cieloResolver,
			Validator: webhook.HeaderSecret{Header: "X-Perata-Notification"}, MaxBodyBytes: 64 << 10,
			ReencodeForm: true, ProcessSync: f,
			Statuses: webhook.Statuses{Unresolved: http.StatusNotFound, InvalidSignature: http.StatusNotFound, EmptyBody: http.StatusBadRequest},
		}}
	})
}

func notification(path, body, secret string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Perata-Notification", secret)
	}
	return req
}

func TestADynamicReceiverTakesItsTenantAndSecretFromTheRecord(t *testing.T) {
	t.Parallel()
	f := &filing{}
	w := cieloWorld(t, f)
	path := "/webhooks/cielo/" + token("acme", "ep-1")

	if rec := w.send(t, notification(path, `{"PaymentId":"p-1"}`, cieloSecret)); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("a notification to an active endpoint answered %d %q", rec.Code, rec.Body.String())
	}
	if rec := w.send(t, notification(path, `{"PaymentId":"p-1"}`, cieloSecret)); rec.Code != http.StatusOK {
		t.Fatalf("a replay answered %d", rec.Code)
	}
	stored := w.calls(t, "acme")
	if len(stored) != 2 || stored[0].Reference != "ep-1" || stored[0].Status != webhook.CallProcessed || stored[0].Attempts != 1 {
		t.Fatalf("the calls were stored as %+v", stored)
	}
	if w.pending(t) != 0 {
		t.Fatal("a synchronous receiver queued its processing")
	}

	for name, req := range map[string]*http.Request{
		"a tampered token":             notification("/webhooks/cielo/"+token("acme", "ep-1")+"0", `{"a":1}`, cieloSecret),
		"another tenant's endpoint":    notification("/webhooks/cielo/"+token("globex", "ep-1"), `{"a":1}`, cieloSecret),
		"an endpoint turned off":       notification("/webhooks/cielo/"+token("acme", "ep-off"), `{"a":1}`, cieloSecret),
		"the wrong secret":             notification(path, `{"a":1}`, "not-the-secret"),
		"no secret":                    notification(path, `{"a":1}`, ""),
		"the wrong secret, a big body": notification(path, strings.Repeat("x", 64<<10+1), "not-the-secret"),
	} {
		if rec := w.send(t, req); rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d, want 404", name, rec.Code)
		}
	}
	if rec := w.send(t, notification(path, "", cieloSecret)); rec.Code != http.StatusBadRequest {
		t.Errorf("an empty body answered %d, want 400", rec.Code)
	}
	if rec := w.send(t, notification(path, strings.Repeat("x", 64<<10+1), cieloSecret)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a body above 64 KiB answered %d, want 413", rec.Code)
	}
	if rec := w.send(t, notification(path, strings.Repeat("x", 64<<10), cieloSecret)); rec.Code != http.StatusOK {
		t.Errorf("a body of exactly 64 KiB answered %d, want 200", rec.Code)
	}
	if rec := w.send(t, notification("/webhooks/cielo/down.x.y", `{"a":1}`, cieloSecret)); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("a resolver that cannot answer answered %d, want 503", rec.Code)
	}
	if n := len(w.calls(t, "acme")); n != 3 || len(w.calls(t, "globex")) != 0 {
		t.Fatalf("refused calls were stored: acme has %d, globex %d", n, len(w.calls(t, "globex")))
	}
}

func TestAFormWhoseBodyWasReadIsEncodedAgain(t *testing.T) {
	t.Parallel()
	f := &filing{}
	w := cieloWorld(t, f)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/cielo/"+token("acme", "ep-1"), strings.NewReader("PaymentId=p-2&ChangeType=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Perata-Notification", cieloSecret)
	// What a middleware that parses forms leaves: the form, and a body read
	// to its end.
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if rec := w.send(t, req); rec.Code != http.StatusOK {
		t.Fatalf("a form answered %d", rec.Code)
	}
	if stored := w.calls(t, "acme"); len(stored) != 1 || stored[0].Payload != "ChangeType=1&PaymentId=p-2" {
		t.Fatalf("the form was stored as %+v", stored)
	}
}

func TestASynchronousProcessorThatFailsKeepsTheCallFailed(t *testing.T) {
	t.Parallel()
	f := &filing{fail: errors.New("the inbox is locked")}
	w := install(t, func(c *webhook.Config, _ *handled) {
		c.Receivers = []webhook.Receiver{{
			Name: "cielo-master", Path: "cielo/master/{environment}", Tenant: "platform", Secret: cieloSecret,
			Validator: webhook.HeaderSecret{Header: "X-Perata-Notification"}, ProcessSync: f,
			Statuses: webhook.Statuses{InvalidSignature: http.StatusNotFound, EmptyBody: http.StatusBadRequest, Failed: http.StatusServiceUnavailable},
		}}
	})
	if rec := w.send(t, notification("/webhooks/cielo/master/live", `{"a":1}`, cieloSecret)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a processor that failed answered %d, want 503", rec.Code)
	}
	call := w.calls(t, "platform")[0]
	if call.Status != webhook.CallFailed || call.Exception != "the inbox is locked" {
		t.Fatalf("the failed call is %s, %q", call.Status, call.Exception)
	}

	// Processed again from the panel, on the queue, once the inbox is back.
	f.mu.Lock()
	f.fail = nil
	f.mu.Unlock()
	if err := w.module.CallService().Process(context.Background(), manager("platform"), call.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.work(t); err != nil {
		t.Fatal(err)
	}
	if after := w.calls(t, "platform")[0]; after.Status != webhook.CallProcessed || after.Attempts != 2 {
		t.Fatalf("after reprocessing the call is %s with %d attempts", after.Status, after.Attempts)
	}
}

// lprRecords are cameras' integration keys: the organization the path names
// and the tenant the record belongs to are different values on purpose.
var lprRecords = map[string]inbound{
	"key-1": {tenant: "t-acme", id: "key-1", org: "acme", secret: sharedSecret, previous: []string{"previous-secret-previous-secret-"}},
}

var lprResolver = webhook.ResolverFunc(func(r *http.Request) (webhook.Resolution, error) {
	record, ok := lprRecords[r.PathValue("key")]
	if !ok || record.org != r.PathValue("org") {
		return webhook.Resolution{}, errors.New("no such integration")
	}
	return webhook.Resolution{Tenant: record.tenant, Secret: record.secret, PreviousSecrets: record.previous, Reference: record.id}, nil
})

// readings files a reading once, by its delivery id, and answers 201 with
// what it filed, or 200 for a repeat.
type readings struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (p *readings) ProcessNow(_ context.Context, g security.Grant, call *webhook.Call) (webhook.ProcessResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[string]bool{}
	}
	id := call.Header("X-Arandu-Delivery-Id")
	if p.seen[id] {
		return webhook.ProcessResult{Status: http.StatusOK, Body: []byte(`{"duplicate":true}`)}, nil
	}
	p.seen[id] = true
	body, _ := json.Marshal(map[string]any{"passage_id": "pas-" + id, "status": "pending", "duplicate": false})
	return webhook.ProcessResult{Status: http.StatusCreated, Body: body}, nil
}

func signedReading(path, deliveryID, body, secret string, at time.Time) *http.Request {
	ts := strconv.FormatInt(at.Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Arandu-Timestamp", ts)
	req.Header.Set("X-Arandu-Delivery-ID", deliveryID)
	req.Header.Set("X-Arandu-Signature", hwebhook.Sign([]byte(secret), ts, deliveryID, []byte(body)))
	return req
}

func TestAReceiverMountedAtItsPublishedAddressAnswersSynchronously(t *testing.T) {
	t.Parallel()
	w := install(t, func(c *webhook.Config, _ *handled) {
		c.Receivers = []webhook.Receiver{
			{
				Name: "lpr", Mount: "/integracoes/lpr/{org}/{key}", Resolve: lprResolver, Validator: webhook.Arandu{},
				MaxBodyBytes: 64 << 10, StoreHeaders: []string{"X-Arandu-Delivery-Id"}, ProcessSync: &readings{},
				Statuses: webhook.Statuses{InvalidSignature: http.StatusUnauthorized},
			},
			{Name: "cielo", Path: "cielo/{token}", Resolve: cieloResolver, Validator: webhook.HeaderSecret{Header: "X-Perata-Notification"}, ProcessSync: &filing{}},
		}
	})
	var patterns []string
	for _, route := range w.router.Routes() {
		patterns = append(patterns, route.Method+" "+route.Pattern)
	}
	for _, want := range []string{"POST /integracoes/lpr/{org}/{key}", "POST /webhooks/cielo/{token}"} {
		if !slices.Contains(patterns, want) {
			t.Fatalf("the routes are %v, and %s is not among them", patterns, want)
		}
	}
	if paths := w.module.ReceivePaths(); !slices.Equal(paths, []string{"/webhooks/", "/integracoes/lpr/"}) {
		t.Fatalf("ReceivePaths answered %v", paths)
	}

	path, body, now := "/integracoes/lpr/acme/key-1", `{"plate":"BRA2E19"}`, time.Now()
	rec := w.send(t, signedReading(path, "dlv-1", body, sharedSecret, now))
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"passage_id":"pas-dlv-1"`) || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("a new reading answered %d %q", rec.Code, rec.Body.String())
	}
	rec = w.send(t, signedReading(path, "dlv-1", body, sharedSecret, now))
	if rec.Code != http.StatusOK || rec.Body.String() != `{"duplicate":true}` {
		t.Fatalf("a repeated reading answered %d %q", rec.Code, rec.Body.String())
	}
	if rec := w.send(t, signedReading(path, "dlv-2", body, "previous-secret-previous-secret-", now)); rec.Code != http.StatusCreated {
		t.Fatalf("a reading signed with the previous secret answered %d", rec.Code)
	}

	// The tenant is the record's, never the path's.
	if len(w.calls(t, "acme")) != 0 || len(w.calls(t, "t-acme")) != 3 {
		t.Fatalf("the readings were stored in the path's organization: acme %d, t-acme %d", len(w.calls(t, "acme")), len(w.calls(t, "t-acme")))
	}
	for name, req := range map[string]*http.Request{
		"another organization's path": signedReading("/integracoes/lpr/globex/key-1", "dlv-3", body, sharedSecret, now),
		"an unknown key":              signedReading("/integracoes/lpr/acme/key-9", "dlv-3", body, sharedSecret, now),
	} {
		if rec := w.send(t, req); rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d, want 404", name, rec.Code)
		}
	}
	for name, req := range map[string]*http.Request{
		"another secret":    signedReading(path, "dlv-3", body, "another-secret-another-secret-01", now),
		"a stale timestamp": signedReading(path, "dlv-3", body, sharedSecret, now.Add(-10*time.Minute)),
		"a body changed on the way": func() *http.Request {
			r := signedReading(path, "dlv-3", body, sharedSecret, now)
			r.Body = httptestBody(`{"plate":"XXX0000"}`)
			return r
		}(),
	} {
		if rec := w.send(t, req); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s answered %d, want 401", name, rec.Code)
		}
	}
}

func TestTheStandardWebhooksValidatorAcceptsTheCurrentAndThePreviousSecret(t *testing.T) {
	t.Parallel()
	at := time.Unix(1_700_000_000, 0)
	w := install(t, func(c *webhook.Config, _ *handled) {
		c.Receivers = []webhook.Receiver{{
			Name: "standard", Tenant: tenant, Secret: stdSecret, PreviousSecrets: []string{stdOldSecret},
			Validator: webhook.StandardWebhooks{Now: func() time.Time { return at.Add(time.Minute) }},
		}}
	})
	request := func(body, signature string, ts int64) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/webhooks/standard", strings.NewReader(body))
		req.Header.Set("Webhook-Id", stdMessageID)
		req.Header.Set("Webhook-Timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("Webhook-Signature", signature)
		return req
	}
	for name, req := range map[string]*http.Request{
		"the current secret's signature":  request(stdBody, stdSignature, at.Unix()),
		"the previous secret's signature": request(stdBody, stdOldSig, at.Unix()),
		"both, during a rotation":         request(stdBody, "v1,bm9wZQ== "+stdOldSig, at.Unix()),
	} {
		if rec := w.send(t, req); rec.Code != http.StatusOK {
			t.Errorf("%s answered %d, want 200", name, rec.Code)
		}
	}
	for name, req := range map[string]*http.Request{
		"a stale timestamp":   request(stdBody, stdSignature, at.Add(-10*time.Minute).Unix()),
		"a changed body":      request(stdBody+" ", stdSignature, at.Unix()),
		"another version":     request(stdBody, strings.Replace(stdSignature, "v1,", "v2,", 1), at.Unix()),
		"no signature at all": request(stdBody, "", at.Unix()),
	} {
		if rec := w.send(t, req); rec.Code != http.StatusForbidden {
			t.Errorf("%s answered %d, want 403", name, rec.Code)
		}
	}
}

func TestAHeaderSecretRefusesWhenThereIsNoSecret(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	v := webhook.HeaderSecret{Header: "X-Perata-Notification"}
	if v.Valid(req, nil, hwebhook.SecretSet{}) {
		t.Fatal("a missing header matched a missing secret")
	}
	req.Header.Set("X-Perata-Notification", cieloSecret)
	if v.Valid(req, nil, hwebhook.SecretSet{}) || !v.Valid(req, nil, hwebhook.SecretSet{Previous: [][]byte{[]byte(cieloSecret)}}) {
		t.Fatal("HeaderSecret does not compare against every accepted secret, and only those")
	}
	if (webhook.HeaderSecret{}).Valid(req, nil, hwebhook.SecretSet{Current: []byte(cieloSecret)}) {
		t.Fatal("a HeaderSecret naming no header accepted a call")
	}
}
