<p align="center">
  <img src=".github/logo.svg" alt="Arandu" width="180">
</p>

# Arandu Webhook

Webhooks both ways for an Arandu application, in one package: what
[spatie/laravel-webhook-server](https://github.com/spatie/laravel-webhook-server)
and [spatie/laravel-webhook-client](https://github.com/spatie/laravel-webhook-client)
are in Laravel.

- **Sending.** A tenant keeps endpoints: an address, the events it subscribes
  to, a signing secret and extra headers, both sealed at rest. The events outbox
  delivers each event to the endpoints subscribed to it, signed, through
  hesape/webhook's Manager: one durable record and one queued job per event and
  endpoint, a transport that refuses private and loopback addresses, retries with
  backoff and `Retry-After`. A call can also be built in code, as webhook-server's
  `WebhookCall::create()`.
- **Receiving.** A receiver per system that calls the application. A call is
  checked against its signature, offered to a profile, stored with the headers
  the receiver keeps, answered at once, and processed on the queue by the
  receiver's processor. Old calls are cleaned on a schedule.

## Parity with Spatie

### laravel-webhook-server

| Spatie | Here |
| --- | --- |
| `WebhookCall::create()->url()->payload()->useSecret()->dispatch()` | `module.Outgoing().URL().Payload().UseSecret().Dispatch(ctx, g)` |
| `dispatchIf`, `dispatchUnless` | `DispatchIf`, `DispatchUnless` |
| `uuid()` | `UUID()`: one identity to one address is delivered once |
| `withHeaders()` | `WithHeaders()`, refusing the headers the delivery writes |
| `sendRawBody()` | `RawBody()` |
| `DefaultSigner`: hex HMAC-SHA256 of the body in `Signature` | `SignWithHMAC(header)` on a call, `signer: "hmac"` on an endpoint |
| `useTimestamp()` | always: the Arandu signature covers a timestamp and the delivery id |
| `tries`, `ExponentialBackoffStrategy` | hesape/webhook's retries: 5 tries, 5 s to 10 min, and the receiver's `Retry-After` |
| `timeout_in_seconds`, `verify_ssl` | `Server.Timeout`; TLS is always verified |
| `WebhookCallSucceededEvent`, `WebhookCallFailedEvent`, `FinalWebhookCallFailedEvent` | the delivery's record: `EndpointService.Deliveries` and `GET …/deliveries` |
| *(none: the application keeps its own endpoints)* | endpoints per tenant, sealed secret and headers, subscriptions, a test call, the events outbox publisher |

### laravel-webhook-client

| Spatie | Here |
| --- | --- |
| `configs[]` in `config/webhook-client.php` | `Config.Receivers` |
| `Route::webhooks('url', 'name')` | the receiver's route, `ReceivePrefix + "/" + Name` |
| `signing_secret`, `signature_header_name` | `Receiver.Secret` (and `PreviousSecrets` during a rotation), `HMAC{Header}` |
| `DefaultSignatureValidator` | `HMAC{Header: "Signature"}`, the default; `Prefix` reads `sha256=…` signatures |
| `SignatureValidator` | `SignatureValidator`, and `Arandu{}` for hesape's scheme with replay protection |
| `InvalidWebhookSignatureEvent` | `Receiver.OnInvalidSignature` |
| `WebhookProfile`, `ProcessEverythingWebhookProfile` | `Profile`, `ProcessEverything` |
| `RespondsToWebhook`, `DefaultRespondsTo` | `Responder`, `RespondOK`: 200 `{"message":"ok"}` |
| `store_headers` | `Receiver.StoreHeaders`, `"*"` for every header |
| `process_webhook_job` | `Receiver.Process`, a `Processor` run by the queue |
| `WebhookCall` model, `saveException`, `clearException` | `Call`, with `Status`, `Attempts` and `Exception` |
| `delete_after_days` with `model:prune` | `Config.DeleteAfterDays` and the scheduled `webhook.calls.clean` |

### What differs, and why

- **The tenant.** Every endpoint and every call belongs to a tenant. A
  management route takes it from the Grant of the session; a received call takes
  it from its `Receiver`, which the application configured, once the signature
  checked. Nothing in a request chooses it.
- **The body of a received call** is kept exactly as it arrived, because those
  are the bytes the signature was checked over. `Call.JSON` and `Call.Form`
  decode it. Attachments are not stored.
- **An invalid signature is answered 403**, not 500: sending the same bytes again
  cannot make them valid, and a 5xx invites the sender to retry.
- **Outgoing calls are POST with a JSON body**, which is what hesape/webhook
  sends. There is no `dispatchSync`: a delivery is always a durable record and a
  job, so a crash between the two cannot lose one.
- **No events per attempt.** hesape/webhook keeps a record of every delivery
  instead; reading it is how a panel shows the last answer of an endpoint.

## Install

```bash
go get github.com/hyz-is/arandu-webhook@v0.1.0
```

It needs framework v0.56 and hesape v0.58.

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

A receiver is called by a system with no session, so its path is exempted from
the CSRF check:

```go
	middleware.CSRFProtect(csrf, sessions.IDFromRequest, middleware.CSRFExcept(webhookModule.ReceivePrefix()+"/"))
```

The events outbox delivers to the endpoints through the publisher, and the
worker runs the deliveries and the processing of received calls:

```go
	// The relay takes one publisher; an application with several listeners
	// fans out to them, and the module's publisher is one of them.
	relay := events.NewRelay(outbox, webhookModule.Publisher(), events.RelayOptions{Locker: locker})

	// In the worker command, with the application's other handlers.
	if err := webhookModule.RegisterJobHandlers(worker); err != nil {
		return err
	}
```

Then, before the application serves:

```bash
aru migrate
```

The package owns `webhook_server_endpoints` and `webhook_client_calls`, and
returns hesape/webhook's `webhook_deliveries` migration with them. An
application that already runs hesape/webhook's Manager has that one applied, and
the migrator skips a name it has run. The jobs table is the queue's, which the
application already migrates.

## Sending

An endpoint is created through `EndpointService` or the management routes. Its
secret is answered once, in clear, for the person to give the receiver:

```go
endpoint, secret, err := webhookModule.EndpointService().Create(ctx, who, webhook.EndpointRequest{
	Name:   "Billing",
	URL:    "https://billing.example.com/hooks",
	Events: []string{"order.paid"},
	Active: true,
})
```

Every event the outbox relays goes to the active endpoints of its tenant
subscribed to its name, or to `*`. Each request carries:

| header | what it is |
| --- | --- |
| `X-Arandu-Signature` | `sha256=` and the hex HMAC-SHA256 of `timestamp.delivery-id.body` |
| `X-Arandu-Timestamp` | the Unix time of the attempt |
| `X-Arandu-Delivery-ID` | the delivery, the same on every retry |
| the endpoint's `SignatureHeader` | for `signer: "hmac"`: the hex HMAC-SHA256 of the body, webhook-server's DefaultSigner |

`Server.HeaderPrefix` renames the first three, `X-Arandu-` becoming `X-Acme-`.
The signature covers no header's name, so a receiver verifies the same bytes.

A call built in code names one of `Server.Secrets`, and the Grant it is
dispatched with carries hesape/webhook's dispatch action for its tenant:

```go
err := webhookModule.Outgoing().
	URL("https://partner.example.com/hooks").
	Event("order.paid").
	Payload(map[string]any{"order": order.ID}).
	UseSecret("partners").
	SignWithHMAC("Signature").
	Dispatch(ctx, security.SystemGrant(hwebhook.ActionDispatch, tenant))
```

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

1. is read up to `MaxBodyBytes` (1 MiB), or answered 413;
2. is checked by the `Validator`, or answered 403 after `OnInvalidSignature`;
3. is offered to the `Profile`; one it turns down is answered and kept nowhere;
4. is stored with the headers in `StoreHeaders`, and its processing is queued in
   the same transaction;
5. is answered by the `Respond`er, 200 `{"message":"ok"}` by default.

The worker then runs the `Processor` with the Grant of the call's tenant. An
error leaves the call `failed` with its message, and the queue tries again until
the receiver's `Tries` (3) are spent, waiting 10 s, then 100 s. A failed call is
processed again from `CallService.Process` or `POST …/calls/{id}/process`.

The validators:

| validator | checks |
| --- | --- |
| `HMAC{Header, Prefix}` | the hex HMAC-SHA256 of the body; `Prefix: "sha256="` for GitHub-style headers |
| `Arandu{HeaderPrefix, Tolerance}` | hesape's scheme, as another Arandu application sends it, refusing a timestamp more than 5 minutes away |
| `SignatureValidatorFunc` | whatever the sender does |

Every validator receives the current secret and the `PreviousSecrets`, so a
sender can rotate without a gap.

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
| `GET /webhook/calls` | `webhook.calls.index` | `CallList` |
| `GET /webhook/calls/{id}` | `webhook.calls.show` | `CallView` |
| `POST /webhook/calls/{id}/process` | `webhook.calls.process` | `CallProcess` |
| `POST /webhooks/{receiver}` | `webhook.receive.{receiver}` | the signature |

## Who may do what

`EndpointPolicy` and `CallPolicy` allow an action to a subject that carries it,
in its own tenant, and never to a guest. `webhook.Actions()` lists the ten an
application gives through arandu-permission. `CallReceive` and `CallClean` are
given to nobody: they are the receiver's and the clean's own Grants.

Every method of `EndpointService` and `CallService` calls `security.Authorize`
before it reaches the Model, and the Model takes its tenant from the Grant. The
queries are generated by `aru model:build` from `model.go`: `Endpoints(db)`
starts an `*EndpointQuery`, `Calls(db)` a `*CallQuery`, `Deliveries(db)` a
`*DeliveryQuery`, and none of them runs without a Grant.

## Tests

```bash
GOWORK=off go test -race ./...
```

The feature suite runs on SQLite with the real queue: a call received, stored,
processed and reprocessed; a refused signature, a stale timestamp, a rotation;
an event delivered and verified by a test server; and the module sending to its
own receivers, both schemes, end to end.

## License

MIT. See [LICENSE.md](LICENSE.md).
