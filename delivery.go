package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/security"
	httpclient "github.com/arandu-io/hesape/http/client"
	"github.com/arandu-io/hesape/queue/jobs"
)

// DeliverJob is the queued job that makes one attempt of a delivery.
const DeliverJob = "webhook.server.deliver"

// The infrastructure retries of an attempt's job: a database that did not
// answer, an attempt still holding its lease. A failed attempt is not one of
// them; the delivery's own plan schedules the next.
const (
	jobTries      = 10
	leaseHeadroom = 10 * time.Second
	maxErrorRunes = 500
)

var jobBackoff = []time.Duration{5 * time.Second, 30 * time.Second, time.Minute}

// deliverMessage is the job's payload: the delivery, how many attempts it
// had when this one was scheduled, and what scheduled it. A job whose count
// no longer matches the delivery is stale and does nothing, so a redelivery
// and the attempt it overtook never both send.
type deliverMessage struct {
	DeliveryID string `json:"delivery_id"`
	Attempts   int64  `json:"attempts"`
	Trigger    string `json:"trigger"`
}

// waitError asks the queue to run the job again after a while, through the
// RetryAfterDuration the worker reads.
type waitError struct {
	reason string
	wait   time.Duration
}

func (e waitError) Error() string                     { return "webhook: " + e.reason }
func (e waitError) RetryAfterDuration() time.Duration { return e.wait }

// errClaimLost is a settlement whose claim another attempt took over.
var errClaimLost = errors.New("webhook: the attempt's claim was taken over")

// schedule queues the attempt after the given count, due at the given time,
// under the dispatch Grant of the tenant.
func (s *sender) schedule(ctx context.Context, tenant, deliveryID string, attempts int64, trigger string, at time.Time, timeout time.Duration) error {
	if trigger == "" {
		trigger = AttemptScheduled
	}
	//arandu:system-grant the delivery was recorded in this tenant under DeliveryDispatch, by the application or after a policy authorized the act; its attempts run under the same action.
	g := security.SystemGrant(DeliveryDispatch, tenant)
	job, err := jobs.New(g, s.queueName, DeliverJob, deliverMessage{DeliveryID: deliveryID, Attempts: attempts, Trigger: trigger})
	if err != nil {
		return err
	}
	job.RunAt = at
	job.Attributes.Tries = jobTries
	job.Attributes.Backoff = jobBackoff
	job.Attributes.Timeout = timeout + 2*leaseHeadroom
	return s.queue.Push(ctx, g, job)
}

// handle is the job: claim the delivery, make the attempt, settle it.
func (s *sender) handle(ctx context.Context, g security.Grant, j *jobs.Job) error {
	if err := g.Check(DeliveryDispatch); err != nil {
		return err
	}
	var msg deliverMessage
	if err := j.Decode(&msg); err != nil {
		return err
	}
	row, err := Deliveries(s.db).WhereKey(msg.DeliveryID).First(ctx, g)
	if err != nil {
		return err
	}
	if row == nil {
		return nil // cleaned since: nothing left to send
	}
	var endpoint *Endpoint
	if strings.HasPrefix(row.SecretRef, endpointSecretRef) {
		if endpoint, err = Endpoints(s.db).WhereKey(row.EndpointID).First(ctx, g); err != nil {
			return err
		}
	}
	policy := s.policy.clone()
	if endpoint != nil {
		policy = s.policyOf(endpoint)
	}

	now := s.clock()
	token, err := data.NewID()
	if err != nil {
		return err
	}
	claimed, err := Deliveries(s.db).WhereKey(row.ID).Where(func(q *DeliveryQuery) {
		q.Where(func(due *DeliveryQuery) {
			due.Where("status", "=", DeliveryPending).Where("attempts", "=", msg.Attempts).Where("next_attempt_at", "<=", now)
		}).OrWhere(func(abandoned *DeliveryQuery) {
			abandoned.Where("status", "=", DeliveryProcessing).Where("attempts", "=", msg.Attempts+1).Where("lease_until", "<=", now)
		})
	}).Update(ctx, g, map[string]any{
		"status": DeliveryProcessing, "claim_token": token, "lease_until": now.Add(policy.Timeout + leaseHeadroom),
		"attempts": msg.Attempts + 1,
	})
	if err != nil {
		return err
	}
	if claimed == 0 {
		return s.unclaimed(ctx, g, row.ID, msg, now)
	}
	if row, err = Deliveries(s.db).WhereKey(row.ID).First(ctx, g); err != nil || row == nil {
		return err
	}

	// An endpoint turned off keeps its deliveries waiting: the attempt is
	// given back, and turning the endpoint on queues them again. A delivery
	// somebody asked for goes whatever the endpoint's state.
	if endpoint != nil && !endpoint.Active && msg.Trigger != AttemptManual {
		_, err := Deliveries(s.db).WhereKey(row.ID).Where("claim_token", "=", token).Update(ctx, g, map[string]any{
			"status": DeliveryPending, "attempts": msg.Attempts, "claim_token": nil, "lease_until": nil,
		})
		return err
	}

	result := s.attempt(ctx, row, endpoint, policy, now)
	err = s.settle(ctx, g, row, endpoint, policy, token, msg.Attempts+1, msg.Trigger, result)
	if errors.Is(err, errClaimLost) {
		return nil
	}
	return err
}

// unclaimed answers a job that found its delivery not claimable: an attempt
// still in progress, or a delivery not due yet, is asked for again later;
// anything else is a job overtaken by another, which does nothing.
func (s *sender) unclaimed(ctx context.Context, g security.Grant, id string, msg deliverMessage, now time.Time) error {
	row, err := Deliveries(s.db).WhereKey(id).First(ctx, g)
	if err != nil || row == nil {
		return err
	}
	switch {
	case row.Status == DeliveryProcessing && row.Attempts == msg.Attempts+1 && row.LeaseUntil != nil && row.LeaseUntil.After(now):
		return waitError{reason: "the delivery's attempt is still in progress", wait: row.LeaseUntil.Sub(now)}
	case row.Status == DeliveryPending && row.Attempts == msg.Attempts && row.NextAttemptAt != nil && row.NextAttemptAt.After(now):
		return waitError{reason: "the delivery's attempt is not due yet", wait: row.NextAttemptAt.Sub(now)}
	}
	return nil
}

// result is what one attempt came to.
type result struct {
	signedAt   time.Time
	status     int
	code       string
	permanent  bool
	retryAfter time.Duration
	response   string
	duration   time.Duration
}

func (r result) delivered() bool { return r.code == "" }

// The failure codes an attempt records. An HTTP answer outside 2xx is
// "http_status_" and its status.
const (
	FailureEndpointDeleted   = "endpoint_deleted"
	FailureSecretUnavailable = "secret_unavailable"
	FailureUnsupportedScheme = "unsupported_scheme"
	FailureRequestTooLarge   = "request_too_large"
	FailureUnsafeDestination = "unsafe_destination"
	FailureTooManyRedirects  = "too_many_redirects"
	FailureTimeout           = "request_timeout"
	FailureTransport         = "transport_failure"
)

var errRedirectLimit = errors.New("webhook: redirect limit exceeded")

// attempt makes one request: the body as it was recorded, the extra headers,
// the dialect's signature under the secrets signing now.
func (s *sender) attempt(ctx context.Context, d *Delivery, endpoint *Endpoint, policy Policy, now time.Time) result {
	r := result{signedAt: now.Truncate(time.Second)}
	fail := func(code string, permanent bool) result {
		r.code, r.permanent = code, permanent
		if policy.Retry == RetryEveryFailure && code != FailureEndpointDeleted {
			r.permanent = false
		}
		return r
	}
	if strings.HasPrefix(d.SecretRef, endpointSecretRef) && endpoint == nil {
		return fail(FailureEndpointDeleted, true)
	}
	if policy.HTTPSOnly && !strings.HasPrefix(strings.ToLower(d.URL), "https://") {
		return fail(FailureUnsupportedScheme, true)
	}
	if int64(len(d.Body)) > policy.MaxRequestBytes {
		return fail(FailureRequestTooLarge, true)
	}
	keys, err := s.signingFor(d, endpoint, r.signedAt)
	if err != nil {
		return fail(FailureSecretUnavailable, true)
	}
	extra := map[string]string{}
	if d.Headers != "" {
		plain, err := s.sealer.open(d.TenantID, d.ID, "delivery-headers", d.Headers)
		if err != nil || jsonInto(plain, &extra) != nil {
			return fail(FailureSecretUnavailable, true)
		}
	}

	attemptCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, d.URL, strings.NewReader(d.Body))
	if err != nil {
		return fail(FailureUnsupportedScheme, true)
	}
	for name, value := range extra {
		request.Header.Set(name, value)
	}
	if err := sign(request.Header, d, keys, r.signedAt, s.prefix, policy.UserAgent); err != nil {
		return fail(FailureSecretUnavailable, true)
	}

	client := *s.client
	client.Timeout = 0
	if policy.MaxRedirects == 0 {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	} else {
		limit := policy.MaxRedirects
		client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
			if len(via) >= limit {
				return errRedirectLimit
			}
			if policy.HTTPSOnly && next.URL.Scheme != "https" {
				return httpclient.ErrUnsupportedScheme
			}
			return nil
		}
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		r.duration = time.Since(started)
		return fail(transportFailure(err))
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, policy.MaxResponseBytes))
	_ = response.Body.Close()
	r.duration = time.Since(started)
	r.status, r.response = response.StatusCode, excerpt(raw)
	if readErr != nil {
		return fail(transportFailure(readErr))
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return r
	}
	status := response.StatusCode
	retryable := status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests ||
		status >= http.StatusInternalServerError && status <= 599
	if retryable && policy.HonorRetryAfter {
		r.retryAfter = parseRetryAfter(response.Header.Get("Retry-After"), time.Now())
	}
	return fail("http_status_"+strconv.Itoa(status), !retryable)
}

// transportFailure classifies an attempt that got no answer.
func transportFailure(err error) (string, bool) {
	switch {
	case errors.Is(err, httpclient.ErrInternalAddress):
		return FailureUnsafeDestination, true
	case errors.Is(err, httpclient.ErrUnsupportedScheme):
		return FailureUnsupportedScheme, true
	case errors.Is(err, errRedirectLimit):
		return FailureTooManyRedirects, true
	case errors.Is(err, context.DeadlineExceeded):
		return FailureTimeout, false
	}
	return FailureTransport, false
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}

// excerpt is the start of an answer, as one line of valid text.
func excerpt(raw []byte) string {
	text := strings.ToValidUTF8(strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, string(raw)), "")
	if utf8.RuneCountInString(text) <= maxErrorRunes {
		return text
	}
	return string([]rune(text)[:maxErrorRunes])
}

// settle writes what the attempt came to, in one transaction: the delivery,
// fenced by the claim; its attempt; its next attempt queued when it has one;
// and the endpoint's count of deliveries in a row that gave up.
func (s *sender) settle(ctx context.Context, g security.Grant, d *Delivery, endpoint *Endpoint, policy Policy, token string, n int64, trigger string, r result) error {
	now := s.clock()
	return data.Transaction(ctx, s.db, func(ctx context.Context) error {
		values := map[string]any{"claim_token": nil, "lease_until": nil, "response_status": nil}
		if r.status != 0 {
			values["response_status"] = r.status
		}
		var next time.Time
		gaveUp := false
		switch {
		case r.delivered():
			values["status"], values["delivered_at"], values["last_error"] = DeliveryDelivered, now, nil
			values["next_attempt_at"], values["permanent"] = nil, Flag(false)
		case !r.permanent && n < d.MaxAttempts:
			wait := d.WaitAfter(n)
			if policy.HonorRetryAfter && r.retryAfter > wait {
				wait = r.retryAfter
			}
			next = now.Add(wait)
			values["status"], values["next_attempt_at"], values["last_error"] = DeliveryPending, next, r.code
		default:
			gaveUp = true
			values["status"], values["next_attempt_at"], values["last_error"] = DeliveryFailed, nil, r.code
			values["permanent"] = Flag(r.permanent)
		}
		settled, err := Deliveries(s.db).WhereKey(d.ID).Where("claim_token", "=", token).Update(ctx, g, values)
		if err != nil {
			return err
		}
		if settled == 0 {
			return errClaimLost
		}
		if err := s.recordAttempt(ctx, g, d, n, trigger, r, now); err != nil {
			return err
		}
		if !next.IsZero() {
			if err := s.schedule(ctx, data.Tenant(g), d.ID, n, AttemptScheduled, next, policy.Timeout); err != nil {
				return err
			}
		}
		if endpoint == nil {
			return nil
		}
		return s.settleEndpoint(ctx, g, endpoint, policy, r.delivered(), gaveUp && trigger != AttemptManual && r.code != FailureEndpointDeleted, now)
	})
}

// recordAttempt writes the attempt's history row.
func (s *sender) recordAttempt(ctx context.Context, g security.Grant, d *Delivery, n int64, trigger string, r result, now time.Time) error {
	row, err := DeliveryAttempts(s.db).New()
	if err != nil {
		return err
	}
	if row.ID, err = data.NewID(); err != nil {
		return err
	}
	row.TenantID = data.Tenant(g)
	row.DeliveryID, row.EndpointID, row.Attempt, row.Trigger = d.ID, d.EndpointID, n, trigger
	row.Succeeded, row.Error, row.Response = Flag(r.delivered()), r.code, r.response
	if r.status != 0 {
		status := int64(r.status)
		row.ResponseStatus = &status
	}
	row.DurationMS, row.SignedAt, row.CreatedAt = r.duration.Milliseconds(), r.signedAt, now
	_, err = row.Save(ctx, g)
	return err
}

// settleEndpoint moves the endpoint's count of deliveries in a row that gave
// up, atomically, and turns it off once the policy's DisableAfter is
// reached. The turning off is recorded like any other act on it.
func (s *sender) settleEndpoint(ctx context.Context, g security.Grant, endpoint *Endpoint, policy Policy, delivered, gaveUp bool, now time.Time) error {
	switch {
	case delivered:
		_, err := Endpoints(s.db).WhereKey(endpoint.ID).Where("consecutive_failures", ">", 0).Update(ctx, g, map[string]any{"consecutive_failures": 0})
		return err
	case !gaveUp:
		return nil
	}
	if _, err := Endpoints(s.db).WhereKey(endpoint.ID).Increment(ctx, g, "consecutive_failures", 1, nil); err != nil {
		return err
	}
	row, err := Endpoints(s.db).WhereKey(endpoint.ID).First(ctx, g)
	if err != nil || row == nil || !row.ShouldDisable(policy.DisableAfter) {
		return err
	}
	row.Disable(DisabledByFailures, now)
	turned, err := Endpoints(s.db).WhereKey(row.ID).Where("active", "=", Flag(true)).Update(ctx, g, map[string]any{
		"active": row.Active, "disabled_at": row.DisabledAt, "disabled_reason": row.DisabledReason,
	})
	if err != nil || turned == 0 {
		return err
	}
	return s.audit.record(ctx, g, EventEndpointDisabled, aggregateEndpoint, row.ID, map[string]any{
		"reason": DisabledByFailures, "consecutive_failures": row.ConsecutiveFailures,
	})
}

// resume queues again the deliveries an endpoint kept waiting while it was
// off.
func (s *sender) resume(ctx context.Context, g security.Grant, endpoint *Endpoint) error {
	policy := s.policyOf(endpoint)
	now := s.clock()
	return Deliveries(s.db).Where("endpoint_id", "=", endpoint.ID).Where("status", "=", DeliveryPending).OrderBy("id").
		Chunk(ctx, g, 200, func(rows DeliveryCollection, _ int) (bool, error) {
			for _, row := range rows {
				at := now
				if row.NextAttemptAt != nil && row.NextAttemptAt.After(now) {
					at = *row.NextAttemptAt
				}
				if err := s.schedule(ctx, data.Tenant(g), row.ID, row.Attempts, AttemptScheduled, at, policy.Timeout); err != nil {
					return false, err
				}
			}
			return true, nil
		})
}

// clean removes the deliveries that are settled and older than the cutoff,
// and the attempts older than it, in the Grant's tenant.
func (s *sender) clean(ctx context.Context, g security.Grant, cutoff time.Time) error {
	if err := g.Check(DeliveryClean); err != nil {
		return err
	}
	if _, err := DeliveryAttempts(s.db).Where("created_at", "<", cutoff).Delete(ctx, g); err != nil {
		return err
	}
	_, err := Deliveries(s.db).Where("created_at", "<", cutoff).
		WhereIn("status", []any{DeliveryDelivered, DeliveryFailed}).Delete(ctx, g)
	return err
}

func jsonInto(text string, v any) error {
	if err := json.Unmarshal([]byte(text), v); err != nil {
		return fmt.Errorf("webhook: the sealed headers are not readable: %w", err)
	}
	return nil
}
