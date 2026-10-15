<p align="center">
  <img src=".github/logo.svg" alt="Arandu" width="180">
</p>

# Arandu Webhook

Webhooks both ways for an Arandu application, in one package: what
[spatie/laravel-webhook-server](https://github.com/spatie/laravel-webhook-server)
and [spatie/laravel-webhook-client](https://github.com/spatie/laravel-webhook-client)
are in Laravel.

- **Sending.** A tenant keeps endpoints: an address, the events it subscribes
  to, a dialect, a signing secret and extra headers, both sealed at rest, and
  optionally a delivery policy of its own. The module owns the delivery: one
  durable record per message and endpoint, its body frozen, written in the same
  transaction as the job that makes its first attempt; every attempt signed
  when it is made, in the endpoint's dialect -- Arandu, webhook-server's HMAC,
  or Standard Webhooks -- through a transport that refuses internal addresses,
  retried on the ladder the delivery was recorded with, and kept in the
  attempt history. The events outbox delivers through the Publisher, `Send`
  delivers a message the application built, and a call can be built in code,
  as webhook-server's `WebhookCall::create()`.
- **Receiving.** A receiver per system that calls the application, with one
  tenant and secret from the configuration, or resolving each request to a
  record of the application -- its tenant, its secrets, its own validator --
  at the address the sender already uses. A call is checked against its
  signature, offered to a profile, stored with the headers the receiver keeps,
  and processed on the queue after a 200, or at once with the processor's
  answer as the reply. Old calls are cleaned on a schedule.
- **Recorded.** Every management act -- an endpoint created, changed, removed,
  imported, turned on or off, a secret shown or rotated, a test, a
  redelivery, a call processed again -- stores an event in the application's
  outbox in the same transaction, which arandu-activitylog writes as an entry.

## Parity with Spatie

### laravel-webhook-server

| Spatie | Here |
| --- | --- |
| `WebhookCall::create()->url()->payload()->useSecret()->dispatch()` | `module.Outgoing().URL().Payload().UseSecret().Dispatch(ctx, g)` |
| `dispatchIf`, `dispatchUnless` | `DispatchIf`, `DispatchUnless` |
| `uuid()` | `UUID()`: one identity to one address is delivered once |
| `withHeaders()` | `WithHeaders()`, refusing the headers the delivery writes |
| `sendRawBody()` | `RawBody()`, and `Module.Send` for a message to a stored endpoint |
| `DefaultSigner`: hex HMAC-SHA256 of the body in `Signature` | `SignWithHMAC(header)` on a call, `DialectHMAC` on an endpoint, with or without the Arandu headers |
| `useTimestamp()` | always: the Arandu and Standard Webhooks signatures cover a timestamp and the delivery id |
| `tries`, `ExponentialBackoffStrategy` | `Policy.Tries` and `Policy.Backoff`, frozen on each delivery; by default 5 tries, 5 s to 10 min, and the receiver's `Retry-After` |
| `timeout_in_seconds`, `verify_ssl` | `Policy.Timeout`; TLS is always verified |
| `WebhookCallSucceededEvent`, `WebhookCallFailedEvent`, `FinalWebhookCallFailedEvent` | the delivery's record and its attempts: `EndpointService.Deliveries`, `Delivery`, `Attempts` and their routes |
| *(none: the application keeps its own endpoints)* | endpoints per tenant, sealed secret and headers, subscriptions, dialects, a policy each, rotation with an overlap, import, redelivery, turning off after failures, a test call, the events outbox publisher |

### laravel-webhook-client

| Spatie | Here |
| --- | --- |
| `configs[]` in `config/webhook-client.php` | `Config.Receivers` |
| `Route::webhooks('url', 'name')` | the receiver's route: `ReceivePrefix + "/" + Name`, or `Path` with parameters under it, or an absolute `Mount` |
| `signing_secret`, `signature_header_name` | `Receiver.Secret` (and `PreviousSecrets` during a rotation), `HMAC{Header}` |
| *(one config per URL)* | `Receiver.Resolve`: one receiver for many records, each with its own tenant, secrets and validator, found from the path |
| `DefaultSignatureValidator` | `HMAC{Header: "Signature"}`, the default; `Prefix` reads `sha256=…` signatures |
| `SignatureValidator` | `SignatureValidator`, `Arandu{}` for hesape's scheme, `StandardWebhooks{}`, and `HeaderSecret{}` for a secret sent as it is |
| `InvalidWebhookSignatureEvent` | `Receiver.OnInvalidSignature` |
| `WebhookProfile`, `ProcessEverythingWebhookProfile` | `Profile`, `ProcessEverything` |
| `RespondsToWebhook`, `DefaultRespondsTo` | `Responder`, `RespondOK`: 200 `{"message":"ok"}`; `Statuses` for each refusal |
| `store_headers` | `Receiver.StoreHeaders`, `"*"` for every header |
| `process_webhook_job` | `Receiver.Process`, a `Processor` run by the queue, or `Receiver.ProcessSync`, run before the answer, which it gives |
| `WebhookCall` model, `saveException`, `clearException` | `Call`, with `Status`, `Attempts` and `Exception` |
| `delete_after_days` with `model:prune` | `Config.DeleteAfterDays` and the scheduled `webhook.calls.clean` |

### What differs, and why

- **The tenant.** Every endpoint, delivery and call belongs to a tenant. A
  management route takes it from the Grant of the session; a received call takes
  it from its `Receiver`, which the application configured, once the signature
  checked. Nothing in a request chooses it.
- **The body of a received call** is kept exactly as it arrived, because those
  are the bytes the signature was checked over. `Call.JSON` and `Call.Form`
  decode it. Attachments are not stored.
- **An invalid signature is answered 403**, not 500: sending the same bytes again
  cannot make them valid, and a 5xx invites the sender to retry.
- **Outgoing calls are POST with a JSON body.** There is no `dispatchSync`: a
  delivery is always a durable record and a job, so a crash between the two
  cannot lose one.
- **No events per attempt.** Each attempt is a row of the delivery's history
  instead; reading it is how a panel shows "attempt 3 of 7, 503, 2 s".

## Install

```bash
go get github.com/hyz-is/arandu-webhook@v0.3.0
```

It needs framework v0.56 and hesape v0.56. It requires no hesape newer than
the one framework v0.56 is built against, because `framework/view` converts
hesape's `view.Page` to its own and stops compiling with hesape v0.57 or newer:
keep hesape at v0.56 in an application that draws pages with it.

## Wire it

There is no service provider, no container and no discovery: these are the
lines in `bootstrap/app.go`, and there are no others.

```go
import (
	webhook "github.com/hyz-is/arandu-webhook"
)
```

```go
	webhookModule, err := webhook.New(webhook.Config{
		// The application's key: the endpoints' secrets and headers are sealed
		// with a key derived from it.
		Key: fw.App.Key,
		Server: webhook.Server{
			Events:       []string{"order.paid", "order.refunded"},
			HeaderPrefix: "X-Acme",
			Secrets:      map[string]string{"partners": cfg.Webhook.PartnersSecret},
			// Nil is webhook.DefaultPolicy(); see "The delivery policy".
			Policy: nil,
		},
		Receivers: []webhook.Receiver{{
			Name:    "billing",
			Tenant:  tenant, // whose calls these are, from the application's configuration
			Secret:  cfg.Billing.WebhookSecret,
			Process: billingWebhooks, // a webhook.Processor of the application
		}},
	}, db, sessions)
	if err != nil {
		return App{}, err
	}
```

Register it with the others:

```go
	k.Register(
		// ...
		webhookModule,
	)
```

A receiver is called by a system with no session, so its paths are exempted
from the CSRF check -- `ReceivePrefix`, and the fixed part of every `Mount`:

```go
	middleware.CSRFProtect(csrf, sessions.IDFromRequest, middleware.CSRFExcept(webhookModule.ReceivePaths()...))
```

The events outbox delivers to the endpoints through the publisher, and to the
activity log through arandu-activitylog's recorder; the worker makes the
attempts and processes the received calls:

```go
	// The relay takes one publisher, so the application hands each event to
	// its listeners in turn: the activity log, then the endpoints. The
	// module's own management events are logged by the recorder and skipped
	// by the module's publisher.
	recorder := activitylog.NewEventRecorder(activityLogger)
	publish := events.PublisherFunc(func(ctx context.Context, e events.Stored) error {
		if err := recorder.Publish(ctx, e); err != nil {
			return err
		}
		return webhookModule.Publisher().Publish(ctx, e)
	})
	relay := events.NewRelay(outbox, publish, events.RelayOptions{Locker: locker})

	// In the worker command, with the application's other handlers.
	if err := webhookModule.RegisterJobHandlers(worker); err != nil {
		return err
	}
```

Then, before the application serves:

```bash
aru migrate
```

The package owns `webhook_server_endpoints`, `webhook_server_deliveries`,
`webhook_server_delivery_attempts` and `webhook_client_calls`. The jobs table is
the queue's and the `outbox` table is hesape's events', both migrated by the
application: every management act stores its event in the outbox.

## Sending

An endpoint is created through `EndpointService` or the management routes. Its
secret -- `whsec_` and the standard base64 of 32 random bytes -- is answered
once, in clear, for the person to give the receiver:

```go
endpoint, secret, err := webhookModule.EndpointService().Create(ctx, who, webhook.EndpointRequest{
	Name:    "Billing",
	URL:     "https://billing.example.com/hooks",
	Events:  []string{"order.paid"},
	Dialect: webhook.DialectStandardWebhooks,
	Active:  true,
})
```

Every event the outbox relays goes to the active endpoints of its tenant
subscribed to its name, or to `*`, keeping the event's id: an event relayed
twice is delivered once. A message the application built goes to one endpoint
with `Send`, its id and its body sent exactly as given on every attempt:

```go
delivery, err := webhookModule.Send(ctx, security.SystemGrant(webhook.DeliveryDispatch, tenant), endpoint.ID, webhook.Message{
	ID:    "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W", // the Webhook-Id; empty makes one
	Event: "invoice.paid",
	Body:  body, // frozen: every attempt and every redelivery sends these bytes
})
```

### Dialects

| dialect | headers of every attempt |
| --- | --- |
| `arandu` (the default) | `X-Arandu-Signature`: `sha256=` and the hex HMAC-SHA256 of `timestamp.delivery-id.body` under the current secret; `X-Arandu-Timestamp`: the Unix time of the attempt; `X-Arandu-Delivery-Id`: the delivery, the same on every attempt; `User-Agent` of the policy |
| `hmac` | the endpoint's `SignatureHeader` with the hex HMAC-SHA256 of the body, webhook-server's DefaultSigner, beside the three Arandu headers unless `WithoutAranduHeaders` |
| `standard-webhooks` | `Webhook-Id`: the delivery id; `Webhook-Timestamp`: the Unix time of the attempt; `Webhook-Signature`: `v1,` and the standard base64 HMAC-SHA256 of `id.timestamp.body` under the key the `whsec_` secret encodes, once per secret still signing, newest first, separated by a space. Nothing else of ours: no `X-Arandu-*`, and Go's own `User-Agent` when the policy names none |

Every attempt is `POST` with `Content-Type: application/json` and the
endpoint's extra headers. `Server.HeaderPrefix` renames the Arandu headers,
`X-Arandu-` becoming `X-Acme-`; the signature covers no header's name, so a
receiver verifies the same bytes. hesape's `webhook.Verify` verifies the Arandu
signature, and any Standard Webhooks library the other one.

A call built in code names one of `Server.Secrets`, and the Grant it is
dispatched with carries `DeliveryDispatch` for its tenant:

```go
err := webhookModule.Outgoing().
	URL("https://partner.example.com/hooks").
	Event("order.paid").
	Payload(map[string]any{"order": order.ID}).
	UseSecret("partners").
	SignWithHMAC("Signature").
	Dispatch(ctx, security.SystemGrant(webhook.DeliveryDispatch, tenant))
```

`DeliveryDispatch` has the value of hesape/webhook's `ActionDispatch`, so a
Grant v0.1.0 code issued for that action still dispatches.

### The delivery policy

`Server.Policy` is how every delivery is made, and an endpoint may carry its own
(`EndpointRequest.Policy`). The number of attempts and the waits between them
are frozen on each delivery when it is recorded; the rest is read at every
attempt. A zero field means zero: start from `webhook.DefaultPolicy()`.

| field | `DefaultPolicy()` | what it does |
| --- | --- | --- |
| `Tries` | 5 | attempts in all, the first included |
| `Backoff` | 5 s, 30 s, 2 min, 10 min | the wait before each attempt after the first, its last one repeated; no jitter |
| `Retry` | `RetryTransient` | transport errors, 408, 425, 429 and 5xx are tried again, anything else is final; `RetryEveryFailure` tries every failure again |
| `HonorRetryAfter` | true | waits as long as the receiver's `Retry-After` when that is longer |
| `HTTPSOnly` | false | refuses an `http://` address at the form, at dispatch and on a redirect |
| `MaxRedirects` | 5 | 0 follows none: the redirect is the answer, a failure |
| `MaxRequestBytes` | 1 MiB | the largest body a delivery is recorded with |
| `MaxResponseBytes` | 1 MiB | how much of an answer is read; the rest is left, and the status decides |
| `Timeout` | 10 s | one attempt, the answer included |
| `UserAgent` | `Arandu-Webhook/1.0` | empty sends Go's own |
| `DisableAfter` | 0 | turns an endpoint off once that many of its deliveries in a row gave up; 0 never |

A provider whose customers verify Standard Webhooks, for example:

```go
Policy: &webhook.Policy{
	Tries:            7,
	Backoff:          []time.Duration{30 * time.Second, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 5 * time.Hour, 10 * time.Hour},
	Retry:            webhook.RetryEveryFailure,
	HTTPSOnly:        true,
	MaxRedirects:     0,
	MaxRequestBytes:  64 << 10,
	MaxResponseBytes: 64 << 10,
	Timeout:          10 * time.Second,
	DisableAfter:     20,
},
```

Without `Server.HTTPClient` the attempts go out on hesape's guarded client,
whose dialer refuses loopback, private, link-local, multicast and unspecified
addresses, behind a dialer of this module that also refuses the shared address
space 100.64.0.0/10 and checks every address a name resolves to before it
connects to one. No environment proxy is used. A client given in
`Server.HTTPClient` keeps its own transport, which is what a test that delivers
to a local server needs.

### Deliveries, attempts and redelivery

A delivery is `pending` while it waits for an attempt, `processing` while one
is in progress, and ends `delivered` or `failed`. Its attempt takes a claim with
a lease, so two workers, or a worker and a redelivery, never send one attempt
twice. `EndpointService.Deliveries`, `Delivery` and `Attempts` read them, each
attempt with its number, trigger, status, failure code, the first 500
characters of the answer and its duration.

`EndpointService.Redeliver` sends a delivery again now: the same id and the
same body, under a new timestamp and signature. A delivery with no attempt left
is given one more; one whose attempt is in progress is refused with 409.

An endpoint turned off -- by a person with `Disable`, or by the engine after
`DisableAfter` deliveries in a row gave up -- keeps its deliveries waiting;
`Enable`, or an `Update` that turns it on, sends them and clears the count, and
a delivered one resets the count too. A redelivery and a
test go whatever the endpoint's state. The deliveries of a deleted endpoint
fail as `endpoint_deleted`. Settled deliveries and their attempts are removed
after `Server.Retention`, 30 days by default, by the scheduled
`webhook.deliveries.clean`.

### Rotating a secret

```go
secret, err := webhookModule.EndpointService().Rotate(ctx, who, endpoint.ID, 24*time.Hour)
```

The new secret is current at once; the one it replaces keeps signing beside it
for the overlap, so a Standard Webhooks attempt carries both signatures, newest
first, until it retires. A secret still retiring from an earlier rotation is
revoked. The management route rotates with `DefaultRotationOverlap`, a day.

### Importing endpoints from an application

An application moving its own endpoints into this module keeps their ids and
secrets, so its receivers notice nothing:

```go
_, err := webhookModule.EndpointService().Import(ctx, migrationSubject, webhook.ImportRequest{
	ID: "ep_01J9...",
	EndpointRequest: webhook.EndpointRequest{
		Name: "Merchant", URL: "https://merchant.example.com/hooks", Events: []string{"*"},
		Dialect: webhook.DialectStandardWebhooks, Active: true,
	},
	Secret:          current,
	PreviousSecrets: []webhook.PreviousSecret{{Secret: retiring, RetiresAt: retiresAt}},
})
```

The secrets are sealed with this module's key, bound to the tenant and the id.
`EndpointImport` is the data migration's action: `Actions()` does not offer it,
and the subject the migration runs as carries it. Previous secrets already
retired are dropped, and at most `MaxPreviousSecrets` (5) are kept.

## Receiving

```go
var billingWebhooks = webhook.ProcessorFunc(func(ctx context.Context, g security.Grant, call *webhook.Call) error {
	var event struct {
		Type    string `json:"type"`
		Invoice string `json:"invoice"`
	}
	if err := call.JSON(&event); err != nil {
		return err
	}
	return invoices.MarkPaid(ctx, g, event.Invoice)
})
```

A call to `POST /webhooks/billing`:

1. is resolved, when the receiver has `Resolve`, to the record it is addressed
   to, or answered 404 (`Statuses.Unresolved`);
2. is checked by a validator that reads only headers, such as `HeaderSecret`,
   before anything of its body is read;
3. is read up to `MaxBodyBytes` (1 MiB), or answered 413; a form already read
   by a middleware is encoded again with `ReencodeForm`;
4. is checked by the `Validator`, or answered 403 after `OnInvalidSignature`;
5. is refused when empty, if `Statuses.EmptyBody` says with what;
6. is offered to the `Profile`; one it turns down is answered and kept nowhere;
7. is stored with the headers in `StoreHeaders`, in the tenant of its receiver
   or of its record, and its processing is queued in the same transaction;
8. is answered by the `Respond`er, 200 `{"message":"ok"}` by default -- or,
   with `ProcessSync`, processed now and answered with what the processor
   returned.

The worker then runs the `Processor` with the Grant of the call's tenant. An
error leaves the call `failed` with its message, and the queue tries again until
the receiver's `Tries` (3) are spent, waiting 10 s, then 100 s. A failed call is
processed again from `CallService.Process` or `POST …/calls/{id}/process`.

The validators:

| validator | checks |
| --- | --- |
| `HMAC{Header, Prefix}` | the hex HMAC-SHA256 of the body; `Prefix: "sha256="` for GitHub-style headers |
| `Arandu{HeaderPrefix, Tolerance}` | hesape's scheme, as another Arandu application sends it, refusing a timestamp more than 5 minutes away |
| `StandardWebhooks{Tolerance}` | `Webhook-Id`, `Webhook-Timestamp` and a `v1` entry of `Webhook-Signature` under a `whsec_` secret, refusing a timestamp more than 5 minutes away |
| `HeaderSecret{Header}` | a shared secret sent as it is, compared in constant time before the body is read; no secret refuses every call |
| `SignatureValidatorFunc` | whatever the sender does |

Every validator receives the current secret and the `PreviousSecrets`, so a
sender can rotate without a gap.

### Receivers addressed to records

A provider that calls one URL per record of the application -- an inbound
endpoint, an integration key -- is one receiver that resolves the record from
the path. The path parameter only says which record to look for: the tenant is
the record's, and the record's secret checked against the signature is what
admits the call. A receiver can keep an address already published with
`Mount`:

```go
webhook.Receiver{
	Name:     "lpr",
	Mount:    "/integracoes/lpr/{org}/{key}",
	Validator: webhook.Arandu{},
	Resolve: webhook.ResolverFunc(func(r *http.Request) (webhook.Resolution, error) {
		integration, err := integrations.ByKey(r.Context(), r.PathValue("org"), r.PathValue("key"))
		if err != nil {
			return webhook.Resolution{}, err // 404
		}
		return webhook.Resolution{
			Tenant: integration.TenantID, Secret: integration.Secret,
			PreviousSecrets: integration.Retiring, Reference: integration.ID,
		}, nil
	}),
	MaxBodyBytes: 64 << 10,
	Statuses:     webhook.Statuses{InvalidSignature: http.StatusUnauthorized},
	ProcessSync: webhook.SyncProcessorFunc(func(ctx context.Context, g security.Grant, call *webhook.Call) (webhook.ProcessResult, error) {
		reading, duplicate, err := passages.File(ctx, g, call.Reference, call.Body())
		if err != nil {
			return webhook.ProcessResult{}, err // Statuses.Failed
		}
		if duplicate {
			return webhook.ProcessResult{Status: http.StatusOK, Body: []byte(`{"duplicate":true}`)}, nil
		}
		return webhook.ProcessResult{Status: http.StatusCreated, Body: reading}, nil
	}),
}
```

A resolver that cannot answer now -- what it reads is down -- wraps
`ErrReceiverUnavailable`, which answers 503. A record whose calls a different
check admits returns its own `Validator`. A synchronous call is stored like any
other, with the outcome on it, and `CallService.Process` processes it again on
the queue.

| refusal | `Statuses` field | default |
| --- | --- | --- |
| no record for the request | `Unresolved` | 404 |
| the signature does not check | `InvalidSignature` | 403 |
| an empty body | `EmptyBody` | accepted |
| a body above `MaxBodyBytes` | `TooLarge` | 413 |
| a body that cannot be read | `BadRequest` | 400 |
| a resolver that cannot answer | `Unavailable` | 503 |
| a `ProcessSync` error | `Failed` | 500 |

The management events are the acts of people on the panel. A received call is
not one: it is in `webhook_client_calls` already, with its outcome, so it is
not stored again in the outbox.

## Routes

The management routes sit behind `RequireAuth` and answer JSON. With a nil
session store, `New` mounts none of them.

| route | name | action |
| --- | --- | --- |
| `GET /webhook/endpoints` | `webhook.endpoints.index` | `EndpointList` |
| `POST /webhook/endpoints` | `webhook.endpoints.store` | `EndpointCreate` |
| `GET /webhook/endpoints/{id}` | `webhook.endpoints.show` | `EndpointView` |
| `PUT /webhook/endpoints/{id}` | `webhook.endpoints.update` | `EndpointUpdate` |
| `DELETE /webhook/endpoints/{id}` | `webhook.endpoints.destroy` | `EndpointDelete` |
| `GET /webhook/endpoints/{id}/secret` | `webhook.endpoints.secret` | `EndpointSecret` |
| `POST /webhook/endpoints/{id}/test` | `webhook.endpoints.test` | `EndpointTest` |
| `GET /webhook/endpoints/{id}/deliveries` | `webhook.endpoints.deliveries` | `EndpointView` |
| `POST /webhook/endpoints/{id}/rotate` | `webhook.endpoints.rotate` | `EndpointRotate` |
| `POST /webhook/endpoints/{id}/enable` | `webhook.endpoints.enable` | `EndpointUpdate` |
| `POST /webhook/endpoints/{id}/disable` | `webhook.endpoints.disable` | `EndpointUpdate` |
| `GET /webhook/deliveries/{id}` | `webhook.deliveries.show` | `EndpointView` |
| `GET /webhook/deliveries/{id}/attempts` | `webhook.deliveries.attempts` | `EndpointView` |
| `POST /webhook/deliveries/{id}/redeliver` | `webhook.deliveries.redeliver` | `DeliveryRedeliver` |
| `GET /webhook/calls` | `webhook.calls.index` | `CallList` |
| `GET /webhook/calls/{id}` | `webhook.calls.show` | `CallView` |
| `POST /webhook/calls/{id}/process` | `webhook.calls.process` | `CallProcess` |
| `POST /webhooks/{receiver}`, its `Path` or its `Mount` | `webhook.receive.{receiver}` | the record and the signature |

## Who may do what

`EndpointPolicy` and `CallPolicy` allow an action to a subject that carries it,
in its own tenant, and never to a guest. `webhook.Actions()` lists the twelve an
application gives through arandu-permission. `EndpointImport` is allowed to a
subject that carries it and is not offered. `CallReceive`, `CallClean`,
`DeliveryDispatch` and `DeliveryClean` are given to nobody: they are the
receiver's, the cleans' and the dispatch's own Grants.

Every method of `EndpointService` and `CallService` calls `security.Authorize`
before it reaches the Model, and the Model takes its tenant from the Grant. The
queries are generated by `aru model:build` from `model.go`: `Endpoints(db)`
starts an `*EndpointQuery`, `Calls(db)` a `*CallQuery`, `Deliveries(db)` a
`*DeliveryQuery`, `DeliveryAttempts(db)` a `*DeliveryAttemptQuery`, and none of
them runs without a Grant.

## The activity log

Every management act stores one event in the application's outbox, in the
transaction of the act, carrying the subject that was authorized and the
action; arandu-activitylog's `EventRecorder`, on the same relay, writes it as an
entry. No payload carries a secret, a signature or a header's value.

| event | when |
| --- | --- |
| `webhook.endpoint.created`, `.updated` (before and after), `.deleted`, `.imported` | an endpoint is added, changed, removed or imported |
| `webhook.endpoint.enabled`, `.disabled` | it is turned on or off; off by the engine with the reason `consecutive_failures` |
| `webhook.endpoint.secret_revealed`, `.secret_rotated` | its secret is shown or rotated |
| `webhook.endpoint.tested` | a test call is queued |
| `webhook.delivery.redelivered` | a delivery is sent again |
| `webhook.call.reprocessed` | a received call is processed again |

## Tests

```bash
GOWORK=off go test -race ./...
```

The feature suite runs on SQLite with the real queue: a call received, stored,
processed and reprocessed; a refused signature, a stale timestamp, a rotation;
receivers resolving each call to a record by a signed token or by a key, at
their published addresses, refusing another tenant's record, a tampered token
and a wrong secret, answering synchronously with 201 and then 200 for a repeat;
the shared-secret and Standard Webhooks validators, a form encoded again, the
size limits;
an event delivered and verified by a test server; a Standard Webhooks delivery
checked byte for byte against a vector computed outside the module, through a
rotation; the retry ladder, the policy's limits, the endpoint turned off after
its failures, redelivery and the claim; the internal addresses refused; the
management events in the outbox; and the module sending to its own receivers,
both schemes, end to end.

## License

MIT. See [LICENSE.md](LICENSE.md).
