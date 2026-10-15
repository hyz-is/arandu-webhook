package webhook

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/queue"
	"github.com/arandu-io/hesape/queue/jobs"
	hwebhook "github.com/arandu-io/hesape/webhook"
)

// ProcessJob is the queued job that hands a stored call to its receiver's
// Processor: webhook-client's ProcessWebhookJob.
const ProcessJob = "webhook.process"

// Processor handles a stored call on the queue: webhook-client's
// process_webhook_job. g is the Grant of the call's tenant, for whatever the
// processing reads and writes. An error leaves the call failed, with the
// message kept, and the queue tries again until the receiver's Tries are
// spent; nil marks it processed.
type Processor interface {
	Process(ctx context.Context, g security.Grant, call *Call) error
}

// ProcessorFunc adapts a function to Processor.
type ProcessorFunc func(ctx context.Context, g security.Grant, call *Call) error

// Process calls f.
func (f ProcessorFunc) Process(ctx context.Context, g security.Grant, call *Call) error {
	return f(ctx, g, call)
}

// Profile decides whether a call whose signature checked is stored and
// processed: webhook-client's WebhookProfile. A call it turns down is
// answered like any other and kept nowhere.
type Profile interface {
	ShouldProcess(r *http.Request, body []byte) bool
}

// ProfileFunc adapts a function to Profile.
type ProfileFunc func(r *http.Request, body []byte) bool

// ShouldProcess calls f.
func (f ProfileFunc) ShouldProcess(r *http.Request, body []byte) bool { return f(r, body) }

// ProcessEverything is webhook-client's ProcessEverythingWebhookProfile.
type ProcessEverything struct{}

// ShouldProcess answers true.
func (ProcessEverything) ShouldProcess(*http.Request, []byte) bool { return true }

// Responder answers the sender once a call is taken: webhook-client's
// RespondsToWebhook. call is nil when the Profile turned the call down.
type Responder interface {
	Respond(w http.ResponseWriter, r *http.Request, call *Call) error
}

// ResponderFunc adapts a function to Responder.
type ResponderFunc func(w http.ResponseWriter, r *http.Request, call *Call) error

// Respond calls f.
func (f ResponderFunc) Respond(w http.ResponseWriter, r *http.Request, call *Call) error {
	return f(w, r, call)
}

// RespondOK is webhook-client's DefaultRespondsTo: 200 {"message":"ok"}.
type RespondOK struct{}

// Respond writes the answer.
func (RespondOK) Respond(w http.ResponseWriter, _ *http.Request, _ *Call) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(`{"message":"ok"}`))
	return err
}

// The refusals of a receiver. Each answers the sender with the status it
// carries and no detail.
var (
	// ErrInvalidSignature is a call whose signature does not check, as
	// webhook-client's InvalidWebhookSignature. It is answered 403: sending
	// the same bytes again cannot make it valid, so a 5xx would only invite
	// the sender to retry.
	ErrInvalidSignature = statusError{status: http.StatusForbidden, text: "webhook: the signature is invalid"}
	// ErrBodyTooLarge is a body above the receiver's MaxBodyBytes.
	ErrBodyTooLarge = statusError{status: http.StatusRequestEntityTooLarge, text: "webhook: the body is too large"}
)

type statusError struct {
	status int
	text   string
}

func (e statusError) Error() string   { return e.text }
func (e statusError) HTTPStatus() int { return e.status }

// processMessage is the queued job's payload.
type processMessage struct {
	CallID string `json:"call_id"`
}

// receiver is one configured Receiver with what it needs at request time.
type receiver struct {
	Receiver
	secrets hwebhook.SecretSet
}

// client is the receiving side.
type client struct {
	db        *data.DB
	audit     *auditor
	queue     *queue.DatabaseQueue
	queueName string
	receivers map[string]*receiver
	now       func() time.Time
}

func newClient(db *data.DB, cfg Config, audit *auditor) *client {
	c := &client{
		db: db, audit: audit, queue: queue.NewDatabaseQueue(db), queueName: cfg.Server.Queue,
		receivers: map[string]*receiver{}, now: func() time.Time { return time.Now().UTC() },
	}
	for _, r := range cfg.Receivers {
		set := hwebhook.SecretSet{Current: []byte(r.Secret)}
		for _, previous := range r.PreviousSecrets {
			set.Previous = append(set.Previous, []byte(previous))
		}
		c.receivers[r.Name] = &receiver{Receiver: r, secrets: set}
	}
	return c
}

// receive is webhook-client's WebhookProcessor: the signature, the profile,
// the stored call and its queued processing, the answer.
func (c *client) receive(w http.ResponseWriter, r *http.Request, rc *receiver) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, rc.MaxBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > rc.MaxBodyBytes {
		return ErrBodyTooLarge
	}
	if !rc.Validator.Valid(r, body, rc.secrets) {
		if rc.OnInvalidSignature != nil {
			rc.OnInvalidSignature(r, rc.Name)
		}
		return ErrInvalidSignature
	}
	if !rc.Profile.ShouldProcess(r, body) {
		return rc.Respond.Respond(w, r, nil)
	}
	call, err := c.store(r.Context(), r, rc, body)
	if err != nil {
		return err
	}
	return rc.Respond.Respond(w, r, call)
}

// store keeps the call and queues its processing, in one transaction: a call
// is never stored without its job, nor queued without its row.
func (c *client) store(ctx context.Context, r *http.Request, rc *receiver, body []byte) (*Call, error) {
	//arandu:system-grant the signature checked against the secret the application configured for this receiver, and the tenant is the receiver's, from Config; nothing in the request chose it.
	g := security.SystemGrant(CallReceive, rc.Tenant)
	call, err := Calls(c.db).New()
	if err != nil {
		return nil, err
	}
	if call.ID, err = data.NewID(); err != nil {
		return nil, err
	}
	now := c.now()
	call.TenantID, call.Name, call.Method = data.Tenant(g), rc.Name, r.Method
	call.URL, call.HeaderData, call.Payload = requestURL(r), keptHeaders(r.Header, rc.StoreHeaders), string(body)
	call.Status, call.ProcessedAt, call.CreatedAt, call.UpdatedAt = CallReceived, now, now, now
	err = data.Transaction(ctx, c.db, func(ctx context.Context) error {
		if _, err := call.Save(ctx, g); err != nil {
			return err
		}
		return c.enqueue(ctx, rc, call)
	})
	if err != nil {
		return nil, err
	}
	return call, nil
}

// enqueue queues the processing of a stored call.
func (c *client) enqueue(ctx context.Context, rc *receiver, call *Call) error {
	//arandu:system-grant the job runs in the call's own tenant, which the receiver's configuration named when the call was stored.
	g := security.SystemGrant(CallReceive, call.TenantID)
	job, err := jobs.New(g, c.queueName, ProcessJob, processMessage{CallID: call.ID})
	if err != nil {
		return err
	}
	job.Attributes.Tries = rc.Tries
	job.Attributes.Backoff = backoff(rc.Tries)
	return c.queue.Push(ctx, g, job)
}

// backoff is webhook-server's ExponentialBackoffStrategy: 10, 100, 1000,
// 10000 seconds, then a day.
func backoff(tries int) []time.Duration {
	out := make([]time.Duration, 0, tries)
	wait := 10 * time.Second
	for i := 1; i < tries; i++ {
		if i > 4 {
			out = append(out, 24*time.Hour)
			continue
		}
		out = append(out, wait)
		wait *= 10
	}
	return out
}

// handle is the job: the call, its receiver's Processor, the outcome kept.
func (c *client) handle(ctx context.Context, g security.Grant, j *jobs.Job) error {
	if err := g.Check(CallReceive); err != nil {
		return err
	}
	var msg processMessage
	if err := j.Decode(&msg); err != nil {
		return err
	}
	call, err := Calls(c.db).WhereKey(msg.CallID).First(ctx, g)
	if err != nil {
		return err
	}
	if call == nil {
		return nil // cleaned since: nothing left to process
	}
	rc, ok := c.receivers[call.Name]
	if !ok {
		return errors.New("webhook: no receiver named " + call.Name + " is configured any more")
	}
	call.Attempts++
	failure := rc.Process.Process(ctx, g, call)
	if failure != nil {
		call.Failed(failure, c.now())
	} else {
		call.Processed(c.now())
	}
	if _, err := call.Save(ctx, g); err != nil {
		return errors.Join(failure, err)
	}
	return failure
}

// requestURL is the address the call arrived at.
func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	u := scheme + "://" + r.Host + r.URL.RequestURI()
	if len(u) > hwebhook.MaxURLLength {
		u = u[:hwebhook.MaxURLLength]
	}
	return u
}
