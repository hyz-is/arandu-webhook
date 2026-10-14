---
name: webhook-package
description: Install, wire and use the Arandu Webhook package (Go, Arandu) in an application, to send webhooks to endpoints and to receive them from other systems. Use when the request is to "install Arandu Webhook", "send webhooks", "receive a webhook", "add a webhook endpoint", "verify a webhook signature", "replace spatie webhook-server or webhook-client", "go get github.com/hyz-is/arandu-webhook", "wire it into bootstrap/app.go", "the receiver answers 403", "the receiver answers 419", "deliveries never leave", "the call is stored but never processed", "everything under /webhook returns 403", "it redirects to /auth/login", "no such table", or when a project's go.mod already requires github.com/hyz-is/arandu-webhook. Covers the wiring in bootstrap/app.go, the CSRF exemption, the relay and the worker, the Config, Server and Receiver fields, the routes, the actions, and the migration step that is not optional.
license: MIT
metadata:
  audience: app
---

# Using Arandu Webhook

Webhooks both ways: endpoints a tenant sends events to, delivered through
hesape/webhook's Manager, and receivers other systems call, whose calls are
stored and processed on the queue. It is registered by hand — there is no
service provider, no container and no discovery, so if a line is not written in
the application, it does not happen.

## Install

```bash
go get github.com/hyz-is/arandu-webhook@v0.1.0
```

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

Three more lines, each where the thing it touches is built:

| where | line | without it |
| --- | --- | --- |
| the CSRF middleware | `middleware.CSRFExcept(webhookModule.ReceivePrefix()+"/")` | every receiver answers 419 |
| the events relay | `webhookModule.Publisher()` among the relay's publishers | events reach no endpoint |
| the worker command | `webhookModule.RegisterJobHandlers(worker)` | deliveries and received calls wait forever |

`New` returns an error rather than starting half-wired: a missing or short
`Key`, a nil database handle, a receiver with no tenant, secret or processor, a
prefix that cannot be a route. A nil session store is allowed and mounts no
management route.

## Then run the migrations

```bash
aru migrate
```

Not optional, and not automatic: `webhook_server_endpoints`,
`webhook_client_calls`, and hesape/webhook's `webhook_deliveries`. The jobs
table is the queue's. **Symptom:** `no such table` from a route that authorized
correctly.

## Configuration

| field | meaning |
| --- | --- |
| `Key` | required: the application's key; the endpoints' secrets and headers are sealed with a key derived from it |
| `Prefix` | the management routes, `/webhook` by default |
| `ReceivePrefix` | the receivers, `/webhooks` by default |
| `PageSize` | a page of the listings, 25 by default, refused above 200 |
| `Server.Events` | the events an endpoint may subscribe to; empty accepts any name |
| `Server.HeaderPrefix` | renames `X-Arandu-` on the deliveries |
| `Server.Secrets` | named secrets for `Outgoing` calls, 32 bytes or more |
| `Server.Queue`, `UserAgent`, `Timeout`, `Retention`, `HTTPClient` | the Manager underneath |
| `Receivers` | one per system that calls the application |
| `DeleteAfterDays`, `CleanSpec` | the clean of received calls, 30 days, daily at 03:20 |

A receiver's `Tenant` is whose calls these are, from the application's
configuration. Nothing in a request chooses it: the signature admits the call,
and the tenant is the receiver's.

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
arandu-permission. **Symptom:** every management route answers 403 for a
signed-in administrator. The subject has roles and none of the actions.
