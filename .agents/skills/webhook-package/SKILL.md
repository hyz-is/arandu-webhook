---
name: webhook-package
description: Install, wire and use the Arandu Webhook package (Go, Arandu) in an application, to send webhooks to endpoints and to receive them from other systems. Use when the request is to "install Arandu Webhook", "send webhooks", "receive a webhook", "add a webhook endpoint", "verify a webhook signature", "replace spatie webhook-server or webhook-client", "go get github.com/hyz-is/arandu-webhook", "wire it into bootstrap/app.go", "the receiver answers 403", "the receiver answers 419", "deliveries never leave", "the delivery stays pending", "send Standard Webhooks", "rotate a webhook secret", "redeliver a webhook", "import our webhook endpoints", "the call is stored but never processed", "everything under /webhook returns 403", "it redirects to /auth/login", "no such table", or when a project's go.mod already requires github.com/hyz-is/arandu-webhook. Covers the wiring in bootstrap/app.go, the CSRF exemption, the relay, the activity log and the worker, the Config, Server, Policy and Receiver fields, the dialects, Send, rotation, import and redelivery, the routes, the actions, and the migration step that is not optional.
license: MIT
metadata:
  audience: app
---

# Using Arandu Webhook

Webhooks both ways: endpoints a tenant sends events to, delivered by this
module's own engine, and receivers other systems call, whose calls are stored
and processed on the queue. It is registered by hand -- there is no service
provider, no container and no discovery, so if a line is not written in the
application, it does not happen.

This module is the application's delivery engine. Do not build another one in
the application -- its own deliveries table, retry loop or HTTP client for
webhooks: a dialect or a policy it lacks is asked for in this module.

## Install

```bash
go get github.com/hyz-is/arandu-webhook@v0.2.0
```

It requires framework v0.56 and hesape v0.56. Keep hesape at v0.56:
framework v0.56's `framework/view` does not compile with hesape v0.57 or newer.

## The wiring, all of it in bootstrap/app.go

```go
import (
	webhook "github.com/hyz-is/arandu-webhook"
)
```

```go
	webhookModule, err := webhook.New(webhook.Config{
		Key: fw.App.Key,
		Server: webhook.Server{Events: []string{"order.paid"}},
		Receivers: []webhook.Receiver{{
			Name: "billing", Tenant: tenant, Secret: billingSecret, Process: billingProcessor,
		}},
	}, db, sessions)
	if err != nil {
		return App{}, err
	}
```

```go
	k.Register(
		// ...
		webhookModule,
	)
```

Four more lines, each where the thing it touches is built:

| where | line | without it |
| --- | --- | --- |
| the CSRF middleware | `middleware.CSRFExcept(webhookModule.ReceivePrefix()+"/")` | every receiver answers 419 |
| the events relay | `webhookModule.Publisher()` among the relay's publishers | events reach no endpoint |
| the events relay | arandu-activitylog's `NewEventRecorder(logger)` among them | the management events are stored and never logged |
| the worker command | `webhookModule.RegisterJobHandlers(worker)` | deliveries and received calls wait forever |

The relay takes one publisher: hand each event to the recorder and then to
`webhookModule.Publisher()` from an `events.PublisherFunc`. The module's
publisher skips its own management events.

`New` returns an error rather than starting half-wired: a missing or short
`Key`, a nil database handle, a receiver with no tenant, secret or processor, a
prefix that cannot be a route, a `Policy` that cannot work. A nil session store
is allowed and mounts no management route.

## Then run the migrations

```bash
aru migrate
```

Not optional, and not automatic: `webhook_server_endpoints`,
`webhook_server_deliveries`, `webhook_server_delivery_attempts` and
`webhook_client_calls`, beside the queue's jobs table and hesape's events
`outbox`, which every management act writes to. **Symptom:** `no such table`
from a route that authorized correctly; `no such table: outbox` from creating
an endpoint.

Coming from v0.1.0: drain the worker of the `webhook.deliver` jobs first, and
read UPGRADE.md.

## Configuration

| field | meaning |
| --- | --- |
| `Key` | required: the application's key; the endpoints' secrets and headers are sealed with a key derived from it |
| `Prefix` | the management routes, `/webhook` by default |
| `ReceivePrefix` | the receivers, `/webhooks` by default |
| `PageSize` | a page of the listings, 25 by default, refused above 200 |
| `Server.Events` | the events an endpoint may subscribe to; empty accepts any name |
| `Server.HeaderPrefix` | renames `X-Arandu-` on the Arandu dialect |
| `Server.Secrets` | named secrets for `Outgoing` calls, 32 bytes or more |
| `Server.Policy` | how every delivery is made; nil is `webhook.DefaultPolicy()` (5 tries, 5 s to 10 min, Retry-After, 408/425/429/5xx retried) |
| `Server.UserAgent`, `Timeout` | laid over the default policy, only when `Policy` is nil |
| `Server.Queue`, `Retention`, `HTTPClient`, `Now` | the queue, how long settled deliveries are kept (30 days), the client a test injects, the clock a test moves |
| `Receivers` | one per system that calls the application |
| `DeleteAfterDays`, `CleanSpec` | the clean of received calls, 30 days, and of deliveries, daily at 03:20 |

A receiver's `Tenant` is whose calls these are, from the application's
configuration. Nothing in a request chooses it: the signature admits the call,
and the tenant is the receiver's.

## Sending

- An endpoint has a dialect: `webhook.DialectArandu` (default),
  `DialectHMAC` (with `WithoutAranduHeaders` to send the HMAC header alone) or
  `DialectStandardWebhooks` (`Webhook-Id`, `Webhook-Timestamp`,
  `Webhook-Signature`, one `v1,` entry per secret still signing).
- A message the application built goes to one endpoint, its id and body exactly
  as given: `webhookModule.Send(ctx, security.SystemGrant(webhook.DeliveryDispatch, tenant), endpointID, webhook.Message{ID, Event, Body})`.
- `EndpointService().Rotate(ctx, who, id, 24*time.Hour)` makes a new secret;
  the old one signs beside it until it retires.
- `EndpointService().Redeliver(ctx, who, deliveryID)` sends the same id and
  body again, signed now. `Deliveries`, `Delivery` and `Attempts` are the
  panel's history.
- `EndpointService().Import(ctx, subject, webhook.ImportRequest{...})` moves an
  application's own endpoints in with their ids and secrets. The subject
  carries `webhook.EndpointImport`, which `Actions()` does not offer.

**Symptom:** a delivery stays `pending` and nothing goes out. No worker runs the
`webhooks` queue, or the endpoint is turned off -- by a person or after
`Policy.DisableAfter` deliveries in a row gave up; `Enable` sends what waited.

**Symptom:** a delivery failed with `unsafe_destination`. The address resolves to
loopback, a private, link-local or shared (100.64.0.0/10) network. That is the
guard working.

## Routes

The management routes sit behind `RequireAuth`, mounted by the package itself.
A request with no session is sent to `/auth/login`. They answer JSON, and the
README lists them. The receivers, `POST /webhooks/{name}`, need no session.

**Symptom:** a receiver answers 403. The signature did not check: the secret, the
header name (`HMAC{Header: …}`), a prefix such as `sha256=` (`HMAC{Prefix: …}`),
or a body changed by a proxy. `OnInvalidSignature` is where to log it.

**Symptom:** a call is stored with status `received` and stays there. No worker
runs the `webhooks` queue, or `RegisterJobHandlers` was not called on it.

## Who may do what

The policies allow an action to a subject that carries it, in its own tenant.
Give the people who manage webhooks the actions of `webhook.Actions()` through
arandu-permission, among them `EndpointRotate` and `DeliveryRedeliver`.
**Symptom:** every management route answers 403 for a signed-in administrator.
The subject has roles and none of the actions.
