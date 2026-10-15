package feature_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/framework/validation"
	"github.com/arandu-io/hesape/database/migrations"
	"github.com/arandu-io/hesape/events"
	hwebhook "github.com/arandu-io/hesape/webhook"

	webhook "github.com/hyz-is/arandu-webhook"
)

// The Standard Webhooks vector these tests pin. The signatures were computed
// outside this module, from the specification: HMAC-SHA256 of id.ts.body under
// the key the whsec_ secret encodes, in standard base64 with padding.
const (
	stdSecret    = "whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	stdOldSecret = "whsec_ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
	stdMessageID = "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W"
	stdBody      = `{"id":"msg_2KWPBgLlAfxdpx2AI54pPJ85f4W","type":"invoice.paid","timestamp":"2023-11-14T22:13:20Z","data":{"invoice":"inv_1","amount":4700}}`
	stdSignature = "v1,xkzC1DPLuj1G4BQuD1MAdU2iLrR7rILV7UYJGFCfuq4="
	stdOldSig    = "v1,VlriHd0ErxpAgNbg8Nwbz1W8gNZJ504XC4XlvTo2U3M="
)

// epoch is the fixed clock the deliveries start at. It is in the past, so a
// job queued for a time on this clock is due on the queue's.
var epoch = time.Unix(1_700_000_000, 0).UTC()

// clock is the module's clock, moved by the test.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func newClock(at time.Time) *clock { return &clock{at: at} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) Set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
}

func (c *clock) Advance(d time.Duration) { c.Set(c.Now().Add(d)) }

// target is a receiver's server: it keeps what it is sent and answers what
// the test tells it to.
type target struct {
	mu      sync.Mutex
	got     []request
	answer  func(w http.ResponseWriter, r *http.Request)
	srv     *httptest.Server
	baseURL string
}

type request struct {
	path   string
	header http.Header
	body   []byte
}

func newTarget(t *testing.T, secure bool) *target {
	t.Helper()
	tg := &target{answer: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		tg.mu.Lock()
		tg.got = append(tg.got, request{path: r.URL.Path, header: r.Header.Clone(), body: body})
		answer := tg.answer
		tg.mu.Unlock()
		answer(w, r)
	})
	if secure {
		tg.srv = httptest.NewTLSServer(handler)
	} else {
		tg.srv = httptest.NewServer(handler)
	}
	tg.baseURL = tg.srv.URL
	t.Cleanup(tg.srv.Close)
	return tg
}

func (tg *target) respond(answer func(w http.ResponseWriter, r *http.Request)) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	tg.answer = answer
}

func (tg *target) status(code int) {
	tg.respond(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
}

func (tg *target) requests() []request {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return append([]request(nil), tg.got...)
}

// strictPolicy is the policy of a provider whose customers verify Standard
// Webhooks: seven attempts on a fixed ladder, every failure retried, https
// only, no redirect, 64 KiB each way, ten seconds, Go's own user agent, and
// the endpoint turned off after twenty deliveries in a row gave up.
func strictPolicy() *webhook.Policy {
	return &webhook.Policy{
		Tries:            7,
		Backoff:          []time.Duration{30 * time.Second, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 5 * time.Hour, 10 * time.Hour},
		Retry:            webhook.RetryEveryFailure,
		HTTPSOnly:        true,
		MaxRedirects:     0,
		MaxRequestBytes:  64 << 10,
		MaxResponseBytes: 64 << 10,
		Timeout:          10 * time.Second,
		DisableAfter:     20,
	}
}

// strictWorld is a world on the fixed clock, sending under the strict policy
// to the target.
func strictWorld(t *testing.T, tg *target, clk *clock, configure func(*webhook.Config)) *world {
	t.Helper()
	return install(t, func(c *webhook.Config, _ *handled) {
		c.Server.HTTPClient = tg.srv.Client()
		c.Server.Policy = strictPolicy()
		c.Server.Now = clk.Now
		if configure != nil {
			configure(c)
		}
	})
}

// importer is the subject a data migration runs as.
func importer(tenantID string) security.Subject {
	return security.Subject{ID: "migration", Tenant: tenantID, Actions: []security.Action{webhook.EndpointImport}, Verified: true}
}

func dispatch(tenantID string) security.Grant {
	return security.SystemGrant(webhook.DeliveryDispatch, tenantID)
}

func importStandard(t *testing.T, w *world, id, url, secret string, previous ...webhook.PreviousSecret) *webhook.Endpoint {
	t.Helper()
	endpoint, err := w.module.EndpointService().Import(context.Background(), importer(tenant), webhook.ImportRequest{
		ID: id,
		EndpointRequest: webhook.EndpointRequest{
			Name: "Merchant", URL: url, Events: []string{"*"}, Dialect: webhook.DialectStandardWebhooks, Active: true,
		},
		Secret: secret, PreviousSecrets: previous,
	})
	if err != nil {
		t.Fatalf("importing %s: %v", id, err)
	}
	return endpoint
}

func (w *world) delivery(t *testing.T, id string) *webhook.Delivery {
	t.Helper()
	row, err := webhook.Deliveries(w.db).WhereKey(id).First(context.Background(), dispatch(tenant))
	if err != nil || row == nil {
		t.Fatalf("reading delivery %s: %v", id, err)
	}
	return row
}

func (w *world) endpoint(t *testing.T, id string) *webhook.Endpoint {
	t.Helper()
	row, err := webhook.Endpoints(w.db).WhereKey(id).First(context.Background(), dispatch(tenant))
	if err != nil || row == nil {
		t.Fatalf("reading endpoint %s: %v", id, err)
	}
	return row
}

// drain runs every job that is due on the queue.
func (w *world) drain(t *testing.T) {
	t.Helper()
	for i := 0; i < 20; i++ {
		due, err := w.jobs.PendingSize(context.Background(), webhook.DefaultQueue)
		if err != nil {
			t.Fatal(err)
		}
		if due == 0 {
			return
		}
		_ = w.work(t)
	}
}

// verifyStandard is a receiver's verification, written from the
// specification rather than from the module: which of the header's v1
// entries the secret signed.
func verifyStandard(secret, id, timestamp string, body []byte, header string) []bool {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return nil
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	expected := mac.Sum(nil)
	var out []bool
	for _, entry := range strings.Split(header, " ") {
		version, encoded, ok := strings.Cut(entry, ",")
		given, err := base64.StdEncoding.DecodeString(encoded)
		out = append(out, ok && version == "v1" && err == nil && hmac.Equal(given, expected))
	}
	return out
}

func headerNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestAStandardWebhooksDeliveryIsTheWireAReceiverVerifies(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	w := strictWorld(t, tg, clk, nil)
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret)

	delivery, err := w.module.Send(context.Background(), dispatch(tenant), "ep_merchant_1",
		webhook.Message{ID: stdMessageID, Event: "invoice.paid", Body: []byte(stdBody)})
	if err != nil {
		t.Fatalf("sending: %v", err)
	}
	if delivery.ID != stdMessageID || delivery.Status != webhook.DeliveryPending || delivery.MaxAttempts != 7 {
		t.Fatalf("the delivery was recorded as %+v", delivery)
	}
	// The same message again is the same delivery, and queues nothing.
	again, err := w.module.Send(context.Background(), dispatch(tenant), "ep_merchant_1",
		webhook.Message{ID: stdMessageID, Event: "invoice.paid", Body: []byte(stdBody)})
	if err != nil || again.ID != stdMessageID || w.pending(t) != 1 {
		t.Fatalf("sending the message again answered %v, %v, with %d jobs", again, err, w.pending(t))
	}
	w.drain(t)

	got := tg.requests()
	if len(got) != 1 {
		t.Fatalf("the receiver took %d requests", len(got))
	}
	r := got[0]
	if string(r.body) != stdBody {
		t.Fatalf("the body arrived as %q", r.body)
	}
	if r.header.Get("Webhook-Id") != stdMessageID || r.header.Get("Webhook-Timestamp") != "1700000000" ||
		r.header.Get("Webhook-Signature") != stdSignature || r.header.Get("Content-Type") != "application/json" {
		t.Fatalf("the Standard Webhooks headers are %v", r.header)
	}
	if !strings.HasPrefix(r.header.Get("User-Agent"), "Go-http-client/") {
		t.Fatalf("the User-Agent is %q, want Go's own", r.header.Get("User-Agent"))
	}
	want := []string{"Accept-Encoding", "Content-Length", "Content-Type", "User-Agent", "Webhook-Id", "Webhook-Signature", "Webhook-Timestamp"}
	if names := headerNames(r.header); !slices.Equal(names, want) {
		t.Fatalf("the request carried the headers %v, want exactly %v", names, want)
	}
	if !slices.Equal(verifyStandard(stdSecret, stdMessageID, "1700000000", r.body, r.header.Get("Webhook-Signature")), []bool{true}) {
		t.Fatal("an independent Standard Webhooks verifier refuses the signature")
	}
	if row := w.delivery(t, stdMessageID); row.Status != webhook.DeliveryDelivered || row.Attempts != 1 {
		t.Fatalf("after the attempt the delivery is %s with %d attempts", row.Status, row.Attempts)
	}
}

func TestARotationSignsWithBothSecretsUntilTheOldOneRetires(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	w := strictWorld(t, tg, clk, nil)
	ctx := context.Background()

	// Imported mid-rotation: the old secret retires in an hour.
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret,
		webhook.PreviousSecret{Secret: stdOldSecret, RetiresAt: epoch.Add(time.Hour)},
		webhook.PreviousSecret{Secret: "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 32)), RetiresAt: epoch.Add(-time.Minute)})
	if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{ID: stdMessageID, Event: "invoice.paid", Body: []byte(stdBody)}); err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	if got := tg.requests()[0].header.Get("Webhook-Signature"); got != stdSignature+" "+stdOldSig {
		t.Fatalf("during the overlap the signature is %q, want the current one and then the retiring one", got)
	}

	// A rotation: the new secret signs first, the one that was current
	// second, and the one retiring from before is revoked.
	rotated, err := w.module.EndpointService().Rotate(ctx, manager(tenant), "ep_merchant_1", 24*time.Hour)
	if err != nil || !strings.HasPrefix(rotated, "whsec_") {
		t.Fatalf("rotating answered %q, %v", rotated, err)
	}
	if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{ID: "msg_second", Event: "invoice.paid", Body: []byte(`{"n":2}`)}); err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	second := tg.requests()[1]
	header := second.header.Get("Webhook-Signature")
	ts := second.header.Get("Webhook-Timestamp")
	if entries := strings.Split(header, " "); len(entries) != 2 {
		t.Fatalf("after a rotation the signature has %d entries: %q", len(entries), header)
	}
	if !slices.Equal(verifyStandard(rotated, "msg_second", ts, second.body, header), []bool{true, false}) ||
		!slices.Equal(verifyStandard(stdSecret, "msg_second", ts, second.body, header), []bool{false, true}) ||
		slices.Contains(verifyStandard(stdOldSecret, "msg_second", ts, second.body, header), true) {
		t.Fatalf("the two signatures are not the new secret's and the previous one's, in that order: %q", header)
	}

	// After retires_at the previous secret signs no more.
	clk.Advance(25 * time.Hour)
	if _, err := w.module.EndpointService().Redeliver(ctx, manager(tenant), "msg_second"); err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	third := tg.requests()[2]
	if !slices.Equal(verifyStandard(rotated, "msg_second", third.header.Get("Webhook-Timestamp"), third.body, third.header.Get("Webhook-Signature")), []bool{true}) {
		t.Fatalf("after the old secret retired the signature is %q", third.header.Get("Webhook-Signature"))
	}
}

func TestARedeliveryKeepsTheIDAndTheBodyAndSignsAgain(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	w := strictWorld(t, tg, clk, nil)
	ctx := context.Background()
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret)
	if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{ID: stdMessageID, Event: "invoice.paid", Body: []byte(stdBody)}); err != nil {
		t.Fatal(err)
	}
	w.drain(t)

	clk.Advance(time.Minute)
	cookies := w.signIn(t, manager(tenant))
	if rec := w.as(t, cookies, http.MethodPost, "/webhook/deliveries/"+stdMessageID+"/redeliver", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("the redelivery answered %d %s", rec.Code, rec.Body.String())
	}
	w.drain(t)

	got := tg.requests()
	if len(got) != 2 {
		t.Fatalf("the receiver took %d requests", len(got))
	}
	first, second := got[0], got[1]
	if second.header.Get("Webhook-Id") != stdMessageID || string(second.body) != string(first.body) {
		t.Fatalf("the redelivery carried %q and %q", second.header.Get("Webhook-Id"), second.body)
	}
	if second.header.Get("Webhook-Timestamp") != "1700000060" || second.header.Get("Webhook-Signature") == first.header.Get("Webhook-Signature") {
		t.Fatalf("the redelivery was not signed again: %v", second.header)
	}
	attempts, err := w.module.EndpointService().Attempts(ctx, manager(tenant), stdMessageID)
	if err != nil || len(attempts) != 2 || attempts[1].Trigger != webhook.AttemptManual || attempts[1].Attempt != 2 || !bool(attempts[1].Succeeded) {
		t.Fatalf("the attempts are %v, %v", attempts, err)
	}
	if rec := w.as(t, cookies, http.MethodGet, "/webhook/deliveries/"+stdMessageID+"/attempts", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"trigger":"manual"`) || !strings.Contains(rec.Body.String(), `"response_status":200`) {
		t.Fatalf("the attempts route answered %d %s", rec.Code, rec.Body.String())
	}
}

func TestTheRetryLadderIsFrozenOnTheDeliveryAndEveryFailureCounts(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	tg.status(http.StatusNotFound)
	w := strictWorld(t, tg, clk, nil)
	ctx := context.Background()
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret)
	if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{ID: stdMessageID, Event: "invoice.paid", Body: []byte(stdBody)}); err != nil {
		t.Fatal(err)
	}
	// One job at a time: each attempt queues the next for the time the
	// module's clock says, and running it earlier only sends it back.
	if err := w.work(t); err != nil {
		t.Fatal(err)
	}

	// The endpoint's policy changes after the delivery was recorded; the
	// delivery keeps the ladder it was recorded with.
	other := strictPolicy()
	other.Tries, other.Backoff = 2, []time.Duration{time.Second}
	if _, err := w.module.EndpointService().Update(ctx, manager(tenant), "ep_merchant_1", webhook.EndpointRequest{
		Name: "Merchant", URL: tg.baseURL + "/hooks", Events: []string{"*"}, Dialect: webhook.DialectStandardWebhooks, Active: true, Policy: other,
	}); err != nil {
		t.Fatal(err)
	}

	ladder := []time.Duration{30 * time.Second, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 5 * time.Hour, 10 * time.Hour}
	for i, wait := range ladder {
		row := w.delivery(t, stdMessageID)
		if row.Status != webhook.DeliveryPending || row.Attempts != int64(i+1) || row.NextAttemptAt == nil || !row.NextAttemptAt.Equal(clk.Now().Add(wait)) {
			t.Fatalf("after attempt %d the delivery is %s, %d attempts, next at %v; want the wait %s", i+1, row.Status, row.Attempts, row.NextAttemptAt, wait)
		}
		if len(tg.requests()) != i+1 {
			t.Fatalf("after attempt %d the receiver took %d requests", i+1, len(tg.requests()))
		}
		clk.Set(*row.NextAttemptAt)
		if err := w.work(t); err != nil {
			t.Fatalf("attempt %d: %v", i+2, err)
		}
	}
	row := w.delivery(t, stdMessageID)
	if row.Status != webhook.DeliveryFailed || row.Attempts != 7 || bool(row.Permanent) || row.LastError == nil || *row.LastError != "http_status_404" {
		t.Fatalf("after seven attempts the delivery is %+v", row)
	}
	got := tg.requests()
	if len(got) != 7 {
		t.Fatalf("the receiver took %d requests, want 7", len(got))
	}
	for _, r := range got {
		if r.header.Get("Webhook-Id") != stdMessageID || string(r.body) != stdBody {
			t.Fatalf("an attempt carried another id or body: %v", r.header)
		}
	}
	attempts, err := w.module.EndpointService().Attempts(ctx, manager(tenant), stdMessageID)
	if err != nil || len(attempts) != 7 || attempts[6].Attempt != 7 || *attempts[6].ResponseStatus != 404 {
		t.Fatalf("the attempt history is %v, %v", attempts, err)
	}
	if w.endpoint(t, "ep_merchant_1").ConsecutiveFailures != 1 {
		t.Fatal("a delivery that gave up did not count against its endpoint")
	}
}

func TestTheDefaultPolicyRetriesOnlyWhatAnotherAttemptMayFix(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, false)
	w := install(t, func(c *webhook.Config, _ *handled) {
		c.Server.HTTPClient = tg.srv.Client()
		c.Server.Now = clk.Now
	})
	ctx := context.Background()
	endpoint, _, err := w.module.EndpointService().Create(ctx, manager(tenant), webhook.EndpointRequest{
		Name: "Billing", URL: tg.baseURL + "/hooks", Events: []string{"*"}, Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	tg.respond(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	unavailable, err := w.module.Send(ctx, dispatch(tenant), endpoint.ID, webhook.Message{Event: "order.paid", Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	row := w.delivery(t, unavailable.ID)
	if row.Status != webhook.DeliveryPending || row.MaxAttempts != 5 || !row.NextAttemptAt.Equal(clk.Now().Add(2*time.Minute)) {
		t.Fatalf("a 503 asking for 120 s left the delivery %s, next at %v", row.Status, row.NextAttemptAt)
	}

	tg.status(http.StatusNotFound)
	missing, err := w.module.Send(ctx, dispatch(tenant), endpoint.ID, webhook.Message{Event: "order.paid", Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	if row := w.delivery(t, missing.ID); row.Status != webhook.DeliveryFailed || !bool(row.Permanent) || row.Attempts != 1 {
		t.Fatalf("a 404 under the default policy left the delivery %s, permanent %v, %d attempts", row.Status, row.Permanent, row.Attempts)
	}
	if got := tg.requests(); len(got) != 2 || got[1].header.Get("User-Agent") != webhook.DefaultUserAgent {
		t.Fatalf("the default policy sent %d requests, the last as %q", len(got), got[len(got)-1].header.Get("User-Agent"))
	}
}

func TestAnEndpointIsTurnedOffAfterItsDeliveriesGiveUpInARow(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	tg.status(http.StatusInternalServerError)
	w := strictWorld(t, tg, clk, func(c *webhook.Config) {
		c.Server.Policy.Tries, c.Server.Policy.Backoff, c.Server.Policy.DisableAfter = 1, nil, 2
	})
	ctx := context.Background()
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret)
	for _, id := range []string{"msg_1", "msg_2"} {
		if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{ID: id, Event: "invoice.paid", Body: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
		w.drain(t)
	}
	endpoint := w.endpoint(t, "ep_merchant_1")
	if endpoint.Active || endpoint.DisabledReason != webhook.DisabledByFailures || endpoint.ConsecutiveFailures != 2 || endpoint.DisabledAt == nil {
		t.Fatalf("after two deliveries gave up the endpoint is %+v", endpoint)
	}
	if names := outboxNames(t, w); !slices.Contains(names, webhook.EventEndpointDisabled) {
		t.Fatalf("turning the endpoint off was not recorded: %v", names)
	}

	// While it is off, a delivery waits rather than goes.
	if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{ID: "msg_3", Event: "invoice.paid", Body: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	if len(tg.requests()) != 2 || w.delivery(t, "msg_3").Status != webhook.DeliveryPending {
		t.Fatalf("a delivery to an endpoint turned off went out: %d requests", len(tg.requests()))
	}

	// Turned on, it goes, and a delivered one resets the count.
	tg.status(http.StatusOK)
	if _, err := w.module.EndpointService().Enable(ctx, manager(tenant), "ep_merchant_1"); err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	if row := w.delivery(t, "msg_3"); row.Status != webhook.DeliveryDelivered {
		t.Fatalf("after the endpoint was turned on the delivery is %s", row.Status)
	}
	if endpoint := w.endpoint(t, "ep_merchant_1"); !endpoint.Active || endpoint.ConsecutiveFailures != 0 || endpoint.DisabledAt != nil {
		t.Fatalf("after a delivery the endpoint is %+v", endpoint)
	}
}

func TestTheClaimLetsOnlyOneAttemptGoOut(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	w := strictWorld(t, tg, clk, nil)
	ctx := context.Background()
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret)
	if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{ID: stdMessageID, Event: "invoice.paid", Body: []byte(stdBody)}); err != nil {
		t.Fatal(err)
	}
	// A redelivery asked for before the first attempt ran: two jobs for one
	// attempt.
	if _, err := w.module.EndpointService().Redeliver(ctx, manager(tenant), stdMessageID); err != nil {
		t.Fatal(err)
	}
	if w.pending(t) != 2 {
		t.Fatalf("%d jobs wait, want the scheduled one and the redelivery", w.pending(t))
	}
	w.drain(t)
	if got := len(tg.requests()); got != 1 {
		t.Fatalf("two jobs for one attempt sent %d requests", got)
	}

	// An attempt in progress holds its lease: a redelivery is refused, and a
	// job for it is asked to come back.
	if _, err := webhook.Deliveries(w.db).WhereKey(stdMessageID).Update(ctx, dispatch(tenant), map[string]any{
		"status": webhook.DeliveryProcessing, "claim_token": "another-worker", "lease_until": clk.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.module.EndpointService().Redeliver(ctx, manager(tenant), stdMessageID); !errors.Is(err, webhook.ErrDeliveryInProgress) {
		t.Fatalf("a redelivery during an attempt answered %v", err)
	}
	if got := len(tg.requests()); got != 1 {
		t.Fatalf("an attempt in progress was sent again: %d requests", got)
	}
}

func TestTheTransportKeepsToThePolicy(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	w := strictWorld(t, tg, clk, func(c *webhook.Config) {
		c.Server.Secrets = map[string]string{"partners": sharedSecret}
	})
	ctx := context.Background()

	// https only: refused at the form and at dispatch.
	if _, _, err := w.module.EndpointService().Create(ctx, manager(tenant), webhook.EndpointRequest{
		Name: "Plain", URL: "http://example.com/hooks", Events: []string{"*"}, Active: true,
	}); !errors.As(err, new(validation.Errors)) {
		t.Fatalf("an http endpoint under an https-only policy answered %v", err)
	}
	if err := w.module.Outgoing().URL("http://example.com/hooks").UseSecret("partners").Dispatch(ctx, dispatch(tenant)); !errors.Is(err, webhook.ErrHTTPSRequired) {
		t.Fatalf("an http call under an https-only policy answered %v", err)
	}

	// The request body is capped when it is recorded.
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret)
	if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{Event: "big", Body: []byte(strings.Repeat("x", 64<<10+1))}); !errors.Is(err, webhook.ErrPayloadTooLarge) {
		t.Fatalf("a body above 64 KiB answered %v", err)
	}

	// No redirect is followed: the redirect is the answer, and a failure.
	tg.respond(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hooks" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	redirected, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{Event: "invoice.paid", Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	if row := w.delivery(t, redirected.ID); row.Status != webhook.DeliveryPending || row.LastError == nil || *row.LastError != "http_status_302" {
		t.Fatalf("a redirect left the delivery %s, %v", row.Status, row.LastError)
	}
	for _, r := range tg.requests() {
		if r.path == "/elsewhere" {
			t.Fatal("the redirect was followed")
		}
	}

	// The answer is read up to the cap, and its status decides.
	tg.respond(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("y", 200<<10)))
	})
	large, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{Event: "invoice.paid", Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	if row := w.delivery(t, large.ID); row.Status != webhook.DeliveryDelivered {
		t.Fatalf("a large answer left the delivery %s, %v", row.Status, row.LastError)
	}
	attempts, err := w.module.EndpointService().Attempts(ctx, manager(tenant), large.ID)
	if err != nil || len(attempts) != 1 || len(attempts[0].Response) > 500 {
		t.Fatalf("the attempt kept %d bytes of the answer: %v", len(attempts[0].Response), err)
	}
}

func TestADefaultPolicyFollowsARedirect(t *testing.T) {
	t.Parallel()
	tg := newTarget(t, false)
	tg.respond(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hooks" {
			http.Redirect(w, r, "/moved", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	w := install(t, func(c *webhook.Config, _ *handled) { c.Server.HTTPClient = tg.srv.Client() })
	ctx := context.Background()
	endpoint, _, err := w.module.EndpointService().Create(ctx, manager(tenant), webhook.EndpointRequest{
		Name: "Billing", URL: tg.baseURL + "/hooks", Events: []string{"*"}, Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := w.module.Send(ctx, dispatch(tenant), endpoint.ID, webhook.Message{Event: "order.paid", Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	if row := w.delivery(t, delivery.ID); row.Status != webhook.DeliveryDelivered || len(tg.requests()) != 2 {
		t.Fatalf("a redirect under the default policy left the delivery %s after %d requests", row.Status, len(tg.requests()))
	}
}

func TestTheGuardedTransportRefusesInternalAddresses(t *testing.T) {
	t.Parallel()
	tg := newTarget(t, false)
	// No HTTPClient: the module's own transport, which a test server on
	// loopback cannot be reached through.
	w := install(t, nil)
	ctx := context.Background()
	for _, address := range []string{tg.baseURL + "/hooks", "http://100.64.0.1:9/hooks", "http://10.1.2.3:9/hooks", "http://169.254.169.254/latest"} {
		endpoint, _, err := w.module.EndpointService().Create(ctx, manager(tenant), webhook.EndpointRequest{
			Name: "Internal", URL: address, Events: []string{"*"}, Active: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		delivery, err := w.module.Send(ctx, dispatch(tenant), endpoint.ID, webhook.Message{Event: "order.paid", Body: []byte(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		w.drain(t)
		row := w.delivery(t, delivery.ID)
		if row.Status != webhook.DeliveryFailed || !bool(row.Permanent) || row.LastError == nil || *row.LastError != webhook.FailureUnsafeDestination {
			t.Errorf("a delivery to %s is %s, permanent %v, %v", address, row.Status, row.Permanent, row.LastError)
		}
	}
	if got := len(tg.requests()); got != 0 {
		t.Fatalf("the loopback server took %d requests", got)
	}
}

func TestTheAranduDialectStillVerifiesWithHesape(t *testing.T) {
	t.Parallel()
	tg := newTarget(t, false)
	w := install(t, func(c *webhook.Config, _ *handled) { c.Server.HTTPClient = tg.srv.Client() })
	ctx := context.Background()
	endpoint, secret, err := w.module.EndpointService().Create(ctx, manager(tenant), webhook.EndpointRequest{
		Name: "Platform", URL: tg.baseURL + "/hooks", Events: []string{"*"}, Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := w.module.Send(ctx, dispatch(tenant), endpoint.ID, webhook.Message{Event: "order.paid", Body: []byte(`{"order":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	r := tg.requests()[0]
	for _, name := range []string{"X-Arandu-Delivery-Id", "X-Arandu-Timestamp", "X-Arandu-Signature"} {
		if len(r.header[name]) != 1 {
			t.Fatalf("the request carries no %s under its canonical name: %v", name, headerNames(r.header))
		}
	}
	if r.header.Get("X-Arandu-Delivery-Id") != delivery.ID || r.header.Get("User-Agent") != webhook.DefaultUserAgent {
		t.Fatalf("the Arandu headers are %v", r.header)
	}
	if !hwebhook.Verify(hwebhook.SecretSet{Current: []byte(secret)}, r.header.Get("X-Arandu-Timestamp"), delivery.ID, r.body, r.header.Get("X-Arandu-Signature")) {
		t.Fatal("hesape's Verify refuses the Arandu signature")
	}
}

func TestAnHMACEndpointCanSendItsSignatureAlone(t *testing.T) {
	t.Parallel()
	tg := newTarget(t, false)
	w := install(t, func(c *webhook.Config, _ *handled) {
		c.Server.HTTPClient = tg.srv.Client()
		c.Server.HeaderPrefix = "X-Acme"
	})
	ctx := context.Background()
	endpoint, secret, err := w.module.EndpointService().Create(ctx, manager(tenant), webhook.EndpointRequest{
		Name: "Legacy", URL: tg.baseURL + "/hooks", Events: []string{"*"}, Active: true,
		Dialect: webhook.DialectHMAC, SignatureHeader: "Signature", WithoutAranduHeaders: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"plate":"BRA2E19"}`
	if _, err := w.module.Send(ctx, dispatch(tenant), endpoint.ID, webhook.Message{Event: "plate.read", Body: []byte(body)}); err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	r := tg.requests()[0]
	want := []string{"Accept-Encoding", "Content-Length", "Content-Type", "Signature", "User-Agent"}
	if names := headerNames(r.header); !slices.Equal(names, want) {
		t.Fatalf("the HMAC call carried %v, want exactly %v", names, want)
	}
	if r.header.Get("Signature") != webhook.SignBody([]byte(secret), []byte(body)) {
		t.Fatalf("the HMAC signature is %q", r.header.Get("Signature"))
	}
}

func TestAnImportKeepsTheIDAndTheSecretInItsTenant(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	w := strictWorld(t, tg, clk, nil)
	ctx := context.Background()
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret)

	secret, err := w.module.EndpointService().Secret(ctx, manager(tenant), "ep_merchant_1")
	if err != nil || secret != stdSecret {
		t.Fatalf("the imported endpoint's secret is %q, %v", secret, err)
	}
	if _, err := w.module.EndpointService().Import(ctx, importer(tenant), webhook.ImportRequest{
		ID: "ep_merchant_1", Secret: stdSecret,
		EndpointRequest: webhook.EndpointRequest{Name: "Again", URL: tg.baseURL, Events: []string{"*"}, Dialect: webhook.DialectStandardWebhooks},
	}); !errors.Is(err, webhook.ErrEndpointExists) {
		t.Fatalf("importing the id again answered %v", err)
	}
	if _, err := w.module.EndpointService().Import(ctx, importer(tenant), webhook.ImportRequest{
		ID: "ep_merchant_2", Secret: "not-a-standard-secret-not-a-standard-secret",
		EndpointRequest: webhook.EndpointRequest{Name: "Bad", URL: tg.baseURL, Events: []string{"*"}, Dialect: webhook.DialectStandardWebhooks},
	}); !errors.As(err, new(validation.Errors)) {
		t.Fatalf("importing a secret Standard Webhooks cannot sign with answered %v", err)
	}
	if _, err := w.module.EndpointService().Import(ctx, manager(tenant), webhook.ImportRequest{
		ID: "ep_merchant_3", Secret: stdSecret,
		EndpointRequest: webhook.EndpointRequest{Name: "Managed", URL: tg.baseURL, Events: []string{"*"}, Dialect: webhook.DialectStandardWebhooks},
	}); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("a manager without EndpointImport imported: %v", err)
	}

	// Another tenant sees nothing of it.
	if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{ID: stdMessageID, Event: "invoice.paid", Body: []byte(stdBody)}); err != nil {
		t.Fatal(err)
	}
	globex := manager("globex")
	if _, err := w.module.EndpointService().Find(ctx, globex, "ep_merchant_1"); !errors.Is(err, webhook.ErrNotFound) {
		t.Errorf("another tenant found the endpoint: %v", err)
	}
	if _, err := w.module.EndpointService().Delivery(ctx, globex, stdMessageID); !errors.Is(err, webhook.ErrNotFound) {
		t.Errorf("another tenant found the delivery: %v", err)
	}
	if _, err := w.module.EndpointService().Attempts(ctx, globex, stdMessageID); !errors.Is(err, webhook.ErrNotFound) {
		t.Errorf("another tenant read the attempts: %v", err)
	}
	if _, err := w.module.EndpointService().Redeliver(ctx, globex, stdMessageID); !errors.Is(err, webhook.ErrNotFound) {
		t.Errorf("another tenant redelivered: %v", err)
	}
	if _, err := w.module.Send(ctx, dispatch("globex"), "ep_merchant_1", webhook.Message{Event: "invoice.paid", Body: []byte(`{}`)}); !errors.Is(err, webhook.ErrNotFound) {
		t.Errorf("another tenant's Grant sent to the endpoint: %v", err)
	}
	if _, err := w.module.Send(ctx, security.SystemGrant(webhook.CallReceive, tenant), "ep_merchant_1", webhook.Message{Event: "invoice.paid", Body: []byte(`{}`)}); !errors.Is(err, security.ErrForbidden) {
		t.Errorf("a Grant for another action sent: %v", err)
	}
}

// outboxReader is the module's handle as the outbox reads it.
type outboxReader struct{ *data.DB }

func (h outboxReader) InTransaction(ctx context.Context) bool { return data.InTransaction(ctx, h.DB) }

func outboxRows(t *testing.T, w *world) []events.Stored {
	t.Helper()
	rows, err := events.NewOutbox(outboxReader{w.db}).Pending(context.Background(), tenant, 500)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func outboxNames(t *testing.T, w *world) []string {
	t.Helper()
	var names []string
	for _, row := range outboxRows(t, w) {
		names = append(names, row.Name)
	}
	return names
}

func TestEveryManagementActIsRecordedInTheOutbox(t *testing.T) {
	t.Parallel()
	tg := newTarget(t, false)
	w := install(t, func(c *webhook.Config, h *handled) {
		c.Server.HTTPClient = tg.srv.Client()
		billing(c, h)
	})
	ctx := context.Background()
	who := manager(tenant)
	endpoints := w.module.EndpointService()

	endpoint, _, err := endpoints.Create(ctx, who, webhook.EndpointRequest{Name: "Billing", URL: tg.baseURL + "/hooks", Events: []string{"*"}, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func() error{
		func() error {
			_, err := endpoints.Update(ctx, who, endpoint.ID, webhook.EndpointRequest{Name: "Billing v2", URL: tg.baseURL + "/hooks", Events: []string{"*"}, Active: true})
			return err
		},
		func() error { _, err := endpoints.Secret(ctx, who, endpoint.ID); return err },
		func() error { _, err := endpoints.Rotate(ctx, who, endpoint.ID, time.Hour); return err },
		func() error { _, err := endpoints.Disable(ctx, who, endpoint.ID); return err },
		func() error { _, err := endpoints.Enable(ctx, who, endpoint.ID); return err },
		func() error {
			delivery, err := endpoints.Test(ctx, who, endpoint.ID)
			if err != nil {
				return err
			}
			w.drain(t)
			_, err = endpoints.Redeliver(ctx, who, delivery.ID)
			return err
		},
		func() error {
			w.send(t, signed("/webhooks/billing", `{"invoice":"inv-1"}`, sharedSecret))
			return w.module.CallService().Process(ctx, who, w.calls(t, tenant)[0].ID)
		},
		func() error { return endpoints.Delete(ctx, who, endpoint.ID) },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}

	want := []string{
		webhook.EventEndpointCreated, webhook.EventEndpointUpdated, webhook.EventSecretRevealed, webhook.EventSecretRotated,
		webhook.EventEndpointDisabled, webhook.EventEndpointEnabled, webhook.EventEndpointTested, webhook.EventDeliveryRedelivered,
		webhook.EventCallReprocessed, webhook.EventEndpointDeleted,
	}
	rows := outboxRows(t, w)
	var names []string
	for _, row := range rows {
		names = append(names, row.Name)
		if row.AuthorizedBy != who.ID || !strings.HasPrefix(row.Action, "webhook.") {
			t.Errorf("%s was recorded as authorized by %q under %q", row.Name, row.AuthorizedBy, row.Action)
		}
		for _, secretish := range []string{"whsec_", "secret\":\"", sharedSecret} {
			if strings.Contains(row.Payload, secretish) {
				t.Errorf("%s carries a secret in its payload: %s", row.Name, row.Payload)
			}
		}
	}
	if !slices.Equal(names, want) {
		t.Fatalf("the outbox recorded %v, want %v", names, want)
	}
	if rows[1].Aggregate != "webhook_endpoint" || rows[1].AggregateID != endpoint.ID || !strings.Contains(rows[1].Payload, `"before"`) {
		t.Fatalf("the update was recorded as %+v", rows[1])
	}

	// The relay hands these events to the Publisher too, which does not
	// deliver them to an endpoint subscribed to every event.
	subscriber, _, err := endpoints.Create(ctx, who, webhook.EndpointRequest{Name: "All", URL: tg.baseURL + "/all", Events: []string{"*"}, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	before := w.pending(t)
	for _, row := range outboxRows(t, w) {
		if err := w.module.Publisher().Publish(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	if w.pending(t) != before {
		t.Fatalf("the Publisher delivered the module's own events to %s", subscriber.ID)
	}
}

func TestTheMigrationsRollBackAndApplyAgain(t *testing.T) {
	t.Parallel()
	w := install(t, nil)
	ctx := context.Background()
	if _, _, err := w.module.EndpointService().Create(ctx, manager(tenant), webhook.EndpointRequest{
		Name: "Kept", URL: "https://example.com/hooks", Events: []string{"*"}, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	declared := w.module.Migrations()
	for i := len(declared) - 1; i >= 0; i-- {
		reversible, ok := declared[i].(migrations.ReversibleMigration)
		if !ok {
			t.Fatalf("%s has no Down", declared[i].GetName())
		}
		if err := reversible.Down(ctx, w.schema); err != nil {
			t.Fatalf("rolling back %s: %v", declared[i].GetName(), err)
		}
	}
	for _, m := range declared {
		if err := m.Up(ctx, w.schema); err != nil {
			t.Fatalf("applying %s again: %v", m.GetName(), err)
		}
	}
	if _, _, err := w.module.EndpointService().Create(ctx, manager(tenant), webhook.EndpointRequest{
		Name: "Again", URL: "https://example.com/hooks", Events: []string{"*"}, Active: true,
	}); err != nil {
		t.Fatalf("after the schema was applied again: %v", err)
	}
}

func TestTurningAnEndpointOnFromItsFormSendsWhatWaited(t *testing.T) {
	t.Parallel()
	clk := newClock(epoch)
	tg := newTarget(t, true)
	w := strictWorld(t, tg, clk, nil)
	ctx := context.Background()
	importStandard(t, w, "ep_merchant_1", tg.baseURL+"/hooks", stdSecret)
	if _, err := w.module.EndpointService().Disable(ctx, manager(tenant), "ep_merchant_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.module.Send(ctx, dispatch(tenant), "ep_merchant_1", webhook.Message{ID: stdMessageID, Event: "invoice.paid", Body: []byte(stdBody)}); err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	if len(tg.requests()) != 0 {
		t.Fatal("a delivery to an endpoint turned off went out")
	}
	if _, err := w.module.EndpointService().Update(ctx, manager(tenant), "ep_merchant_1", webhook.EndpointRequest{
		Name: "Merchant", URL: tg.baseURL + "/hooks", Events: []string{"*"}, Dialect: webhook.DialectStandardWebhooks, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	w.drain(t)
	if row := w.delivery(t, stdMessageID); row.Status != webhook.DeliveryDelivered || len(tg.requests()) != 1 {
		t.Fatalf("after the form turned the endpoint on the delivery is %s, %d requests", row.Status, len(tg.requests()))
	}
}

func TestARowThePreviousReleaseWritesReadsBack(t *testing.T) {
	t.Parallel()
	tg := newTarget(t, false)
	w := install(t, func(c *webhook.Config, _ *handled) { c.Server.HTTPClient = tg.srv.Client() })
	ctx := context.Background()
	created, _, err := w.module.EndpointService().Create(ctx, manager(tenant), webhook.EndpointRequest{
		Name: "Template", URL: tg.baseURL + "/hooks", Events: []string{"*"}, Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// What a binary of the previous release inserts during a rollout: only
	// the columns it knows, the sealed secret copied from a row of its own.
	stored := w.endpoint(t, created.ID)
	if _, err := w.db.ExecContext(ctx, `INSERT INTO webhook_server_endpoints
		(id, tenant_id, name, url, events, signer, signature_header, secret, headers, active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"old-1", tenant, "Old", tg.baseURL+"/old", "*", "hmac", "Signature", stored.Secret, "", 1, time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	old := w.endpoint(t, "old-1")
	if old.Dialect != webhook.DialectArandu || old.PreviousSecrets != "" || old.Policy != "" || !bool(old.AranduHeaders) {
		t.Fatalf("a row of the previous release reads back as %+v", old)
	}
}
