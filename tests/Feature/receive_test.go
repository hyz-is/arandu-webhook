package feature_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arandu-io/framework/security"
	hwebhook "github.com/arandu-io/hesape/webhook"

	webhook "github.com/hyz-is/arandu-webhook"
)

// signed is a request to a receiver, signed as webhook-server's DefaultSigner
// signs: the hex HMAC-SHA256 of the body in the Signature header.
func signed(target, body, secret string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Signature", webhook.SignBody([]byte(secret), []byte(body)))
	req.Header.Set("X-Request-Id", "req-1")
	return req
}

func billing(c *webhook.Config, _ *handled) {
	c.Receivers = []webhook.Receiver{{Name: "billing", Tenant: tenant, Secret: sharedSecret, StoreHeaders: []string{"X-Request-Id"}}}
}

func TestAValidCallIsStoredQueuedAndProcessed(t *testing.T) {
	t.Parallel()
	w := install(t, billing)

	body := `{"event":"invoice.paid","invoice":"inv-1"}`
	rec := w.send(t, signed("/webhooks/billing?source=gateway", body, sharedSecret))
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"message":"ok"}` {
		t.Fatalf("a valid call answered %d %s, want 200 {\"message\":\"ok\"}", rec.Code, rec.Body.String())
	}

	stored := w.calls(t, tenant)
	if len(stored) != 1 {
		t.Fatalf("stored %d calls, want 1", len(stored))
	}
	call := stored[0]
	if call.Name != "billing" || call.Method != http.MethodPost || call.Payload != body || call.Status != webhook.CallReceived {
		t.Fatalf("the call was stored as %+v", call)
	}
	if !strings.HasSuffix(call.URL, "/webhooks/billing?source=gateway") {
		t.Fatalf("the call's URL is %q", call.URL)
	}
	// Only the headers the receiver keeps are kept: not the signature.
	if call.Header("x-request-id") != "req-1" || call.Header("Signature") != "" {
		t.Fatalf("the kept headers are %v", call.Headers())
	}
	if w.pending(t) != 1 {
		t.Fatalf("%d jobs wait, want the one that processes the call", w.pending(t))
	}

	if err := w.work(t); err != nil {
		t.Fatalf("processing: %v", err)
	}
	seen := w.handled.seen()
	if len(seen) != 1 || seen[0].ID != call.ID {
		t.Fatalf("the processor saw %d calls", len(seen))
	}
	var decoded struct{ Invoice string }
	if err := seen[0].JSON(&decoded); err != nil || decoded.Invoice != "inv-1" {
		t.Fatalf("the processor read %+v, %v", decoded, err)
	}
	after := w.calls(t, tenant)[0]
	if after.Status != webhook.CallProcessed || after.Attempts != 1 || after.Exception != "" {
		t.Fatalf("after processing the call is %s, %d attempts, exception %q", after.Status, after.Attempts, after.Exception)
	}
}

func TestAnInvalidSignatureIsRefusedAndNothingIsKept(t *testing.T) {
	t.Parallel()
	refused := 0
	w := install(t, func(c *webhook.Config, h *handled) {
		billing(c, h)
		c.Receivers[0].OnInvalidSignature = func(_ *http.Request, receiver string) {
			if receiver == "billing" {
				refused++
			}
		}
	})

	for name, req := range map[string]*http.Request{
		"another secret": signed("/webhooks/billing", `{"a":1}`, "another-secret-another-secret-01"),
		"no signature":   httptest.NewRequest(http.MethodPost, "/webhooks/billing", strings.NewReader(`{"a":1}`)),
	} {
		if rec := w.send(t, req); rec.Code != http.StatusForbidden {
			t.Errorf("a call with %s answered %d, want 403", name, rec.Code)
		}
	}
	tampered := signed("/webhooks/billing", `{"a":1}`, sharedSecret)
	tampered.Body = httptestBody(`{"a":2}`)
	if rec := w.send(t, tampered); rec.Code != http.StatusForbidden {
		t.Errorf("a call whose body changed after signing answered %d, want 403", rec.Code)
	}
	if refused != 3 {
		t.Errorf("OnInvalidSignature was called %d times, want 3", refused)
	}
	if n := len(w.calls(t, tenant)); n != 0 || w.pending(t) != 0 {
		t.Fatalf("a refused call left %d rows and %d jobs", n, w.pending(t))
	}
}

func TestTheProfileDecidesWhatIsStored(t *testing.T) {
	t.Parallel()
	w := install(t, func(c *webhook.Config, h *handled) {
		billing(c, h)
		c.Receivers[0].Profile = webhook.ProfileFunc(func(_ *http.Request, body []byte) bool {
			return !strings.Contains(string(body), "ping")
		})
	})

	if rec := w.send(t, signed("/webhooks/billing", `{"event":"ping"}`, sharedSecret)); rec.Code != http.StatusOK {
		t.Fatalf("a call the profile turns down answered %d, want 200", rec.Code)
	}
	if n := len(w.calls(t, tenant)); n != 0 {
		t.Fatalf("a call the profile turned down was stored (%d rows)", n)
	}
	if rec := w.send(t, signed("/webhooks/billing", `{"event":"invoice.paid"}`, sharedSecret)); rec.Code != http.StatusOK {
		t.Fatalf("a call the profile takes answered %d", rec.Code)
	}
	if n := len(w.calls(t, tenant)); n != 1 {
		t.Fatalf("stored %d calls, want 1", n)
	}
}

func TestAFailedProcessingKeepsTheMessageAndIsRetried(t *testing.T) {
	t.Parallel()
	w := install(t, billing)
	w.handled.fail = errors.New("the invoice service is down")

	w.send(t, signed("/webhooks/billing", `{"invoice":"inv-2"}`, sharedSecret))
	if err := w.work(t); err == nil {
		t.Fatal("a processor that failed was reported as done")
	}
	call := w.calls(t, tenant)[0]
	if call.Status != webhook.CallFailed || call.Exception != "the invoice service is down" || call.Attempts != 1 {
		t.Fatalf("after a failure the call is %s, %q, %d attempts", call.Status, call.Exception, call.Attempts)
	}

	// Somebody fixes the service and asks for the call again.
	w.handled.fail = nil
	cookies := w.signIn(t, manager(tenant))
	if rec := w.as(t, cookies, http.MethodPost, "/webhook/calls/"+call.ID+"/process", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("reprocessing answered %d %s", rec.Code, rec.Body.String())
	}
	for i := 0; i < 3 && w.calls(t, tenant)[0].Status != webhook.CallProcessed; i++ {
		_ = w.work(t)
	}
	if after := w.calls(t, tenant)[0]; after.Status != webhook.CallProcessed || after.Exception != "" {
		t.Fatalf("after reprocessing the call is %s, %q", after.Status, after.Exception)
	}
}

func TestABodyAboveTheLimitIsRefused(t *testing.T) {
	t.Parallel()
	w := install(t, func(c *webhook.Config, h *handled) {
		billing(c, h)
		c.Receivers[0].MaxBodyBytes = 16
	})
	if rec := w.send(t, signed("/webhooks/billing", strings.Repeat("x", 17), sharedSecret)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body above the limit answered %d, want 413", rec.Code)
	}
}

func TestOnlyTheConfiguredMethodsArrive(t *testing.T) {
	t.Parallel()
	w := install(t, billing)
	req := httptest.NewRequest(http.MethodGet, "/webhooks/billing", nil)
	if rec := w.send(t, req); rec.Code == http.StatusOK {
		t.Fatal("a GET reached a receiver configured for POST")
	}
}

func TestTheAranduValidatorChecksTheSchemeAndRefusesAReplay(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	w := install(t, func(c *webhook.Config, _ *handled) {
		c.Receivers = []webhook.Receiver{{
			Name: "platform", Tenant: tenant, Secret: sharedSecret, PreviousSecrets: []string{"previous-secret-previous-secret-"},
			Validator: webhook.Arandu{HeaderPrefix: "X-Acme", Now: func() time.Time { return now }},
		}}
	})
	request := func(secret string, at time.Time) *http.Request {
		body := `{"event":"plate.read"}`
		ts := strconv.FormatInt(at.Unix(), 10)
		req := httptest.NewRequest(http.MethodPost, "/webhooks/platform", strings.NewReader(body))
		req.Header.Set("X-Acme-Timestamp", ts)
		req.Header.Set("X-Acme-Delivery-ID", "dlv-1")
		req.Header.Set("X-Acme-Signature", hwebhook.Sign([]byte(secret), ts, "dlv-1", []byte(body)))
		return req
	}
	if rec := w.send(t, request(sharedSecret, now)); rec.Code != http.StatusOK {
		t.Fatalf("a call signed with the current secret answered %d", rec.Code)
	}
	if rec := w.send(t, request("previous-secret-previous-secret-", now.Add(-time.Minute))); rec.Code != http.StatusOK {
		t.Fatalf("a call signed with the previous secret during a rotation answered %d", rec.Code)
	}
	if rec := w.send(t, request(sharedSecret, now.Add(-10*time.Minute))); rec.Code != http.StatusForbidden {
		t.Fatalf("a call signed ten minutes ago answered %d, want 403", rec.Code)
	}
}

func TestTheHMACValidatorReadsAPrefixedSignature(t *testing.T) {
	t.Parallel()
	w := install(t, func(c *webhook.Config, _ *handled) {
		c.Receivers = []webhook.Receiver{{Name: "github", Tenant: tenant, Secret: sharedSecret,
			Validator: webhook.HMAC{Header: "X-Hub-Signature-256", Prefix: "sha256="}}}
	})
	body := `{"zen":"keep it simple"}`
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", "sha256="+webhook.SignBody([]byte(sharedSecret), []byte(body)))
	if rec := w.send(t, req); rec.Code != http.StatusOK {
		t.Fatalf("a GitHub-style signature answered %d", rec.Code)
	}
}

func TestAReceiverStoresInItsOwnTenant(t *testing.T) {
	t.Parallel()
	w := install(t, func(c *webhook.Config, _ *handled) {
		c.Receivers = []webhook.Receiver{
			{Name: "billing", Tenant: tenant, Secret: sharedSecret},
			{Name: "partner", Tenant: "globex", Secret: sharedSecret},
		}
	})
	req := signed("/webhooks/partner", `{"tenant":"acme"}`, sharedSecret)
	req.Header.Set("X-Tenant", tenant)
	w.send(t, req)
	if len(w.calls(t, tenant)) != 0 || len(w.calls(t, "globex")) != 1 {
		t.Fatal("a call was stored in a tenant its request named rather than in its receiver's")
	}

	// And a person of one tenant does not see the other's calls.
	cookies := w.signIn(t, manager(tenant))
	call := w.calls(t, "globex")[0]
	if rec := w.as(t, cookies, http.MethodGet, "/webhook/calls/"+call.ID, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("another tenant's call answered %d, want 404", rec.Code)
	}
	rec := w.as(t, w.signIn(t, manager("globex")), http.MethodGet, "/webhook/calls?name=partner", "")
	var page struct {
		Data struct {
			Items []map[string]any `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Data.Items) != 1 {
		t.Fatalf("the call listing answered %d %s", rec.Code, rec.Body.String())
	}
}

func TestTheCleanRemovesOldCalls(t *testing.T) {
	t.Parallel()
	w := install(t, billing)
	w.send(t, signed("/webhooks/billing", `{"old":true}`, sharedSecret))
	old := w.calls(t, tenant)[0]
	old.CreatedAt = time.Now().UTC().AddDate(0, 0, -webhook.DefaultDeleteAfterDays-1)
	if _, err := old.Save(context.Background(), security.SystemGrant(webhook.CallReceive, tenant)); err != nil {
		t.Fatal(err)
	}
	w.send(t, signed("/webhooks/billing", `{"old":false}`, sharedSecret))

	tasks := w.module.Schedule()
	if len(tasks) != 1 || tasks[0].ID != "webhook.calls.clean" {
		t.Fatalf("the module schedules %v", tasks)
	}
	if err := tasks[0].Run(context.Background(), security.Grant{}); err != nil {
		t.Fatal(err)
	}
	left := w.calls(t, tenant)
	if len(left) != 1 || left[0].Payload != `{"old":false}` {
		t.Fatalf("after the clean %d calls are left", len(left))
	}
}
