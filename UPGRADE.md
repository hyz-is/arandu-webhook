# Upgrade Guide

## Unreleased

## v0.3.0

Nothing to rewrite: every field added is optional, and a receiver configured
for v0.2.0 answers as it did -- 403 for an invalid signature, 413 for a body too
large, any body accepted -- except that a body that cannot be read answers 400
instead of 500.

Before deploying, run `aru migrate`:
`20261015_0006_add_reference_to_webhook_client_calls` adds a column with a
default to `webhook_client_calls`.

The clean of received calls, `webhook.calls.clean`, is now a per-tenant task:
the scheduler runs it in every active tenant with that tenant's Grant, instead
of once in the tenants the receivers name.

A receiver with `Mount` answers outside `ReceivePrefix`: exempt it from the
CSRF check with `middleware.CSRFExcept(webhookModule.ReceivePaths()...)` in
place of `CSRFExcept(webhookModule.ReceivePrefix()+"/")`.


## v0.2.0

The module requires hesape v0.56.0, not v0.58.0. An application that went to
hesape v0.58.0 only because of this module can go back with
`go get github.com/arandu-io/hesape@v0.56.0`, which is what framework v0.56.0's
`framework/view` compiles against.

Two signatures changed:

- `(*Module).Manager` is removed. There is no hesape/webhook Manager
  underneath: send to a stored endpoint with `Module.Send`, to an address with
  `Module.Outgoing`, and let the events relay deliver through
  `Module.Publisher`. An application that dispatched through the Manager to
  endpoints of its own stores them as endpoints (`EndpointService.Import`
  keeps their ids and secrets) and sends with `Module.Send`.
- `(*EndpointService).Test` answers `(*Delivery, error)` instead of `error`:
  write `_, err := endpoints.Test(ctx, who, id)`.

Before deploying:

1. Run `aru migrate`. It adds the columns of
   `20261014_0003_add_dialect_and_policy_to_webhook_server_endpoints` and
   creates `webhook_server_deliveries` and `webhook_server_delivery_attempts`.
   Every management act now stores an event in the outbox, so hesape's events
   migrations (the `outbox` table) have to be applied too; an application that
   relays events to the module's Publisher has them already.
2. Let the worker drain the `webhooks` queue of the `webhook.deliver` jobs
   v0.1.0 queued. v0.2.0 registers `webhook.server.deliver` and nothing for
   the old name, so a job left over would be parked as having no handler.
   `webhook_deliveries` keeps v0.1.0's history; drop it when nobody reads it.
3. Give the people who rotate secrets and redeliver `EndpointRotate` and
   `DeliveryRedeliver` through arandu-permission. Enabling and disabling an
   endpoint is `EndpointUpdate`, as before.
4. Feed the relay into arandu-activitylog's `EventRecorder` beside the
   module's Publisher, so the management events become log entries.

Behaviour that changes with no change of code: an endpoint turned off keeps
its deliveries waiting until it is turned on; the deliveries of a deleted
endpoint fail as `endpoint_deleted`; without `Server.HTTPClient` the shared
address space 100.64.0.0/10 is refused and no environment proxy is used; and
an answer is read up to 1 MiB and its status decides. `DefaultPolicy` keeps
v0.1.0's attempts, waits, Retry-After and the statuses it retries.

## v0.1.0

The first release. Install it with hesape v0.58.0 or newer, wire it in
`bootstrap/app.go` as the README shows, exempt `ReceivePrefix()` from the CSRF
check, add `Publisher()` to the events relay and `RegisterJobHandlers` to the
worker, run `aru migrate`, and give the people who manage webhooks the actions
of `Actions()` through arandu-permission.

