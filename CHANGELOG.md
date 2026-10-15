# Changelog

Everything worth knowing about a release of Arandu Webhook is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

### Fixed

- The module requires hesape v0.56.0 instead of v0.58.0. v0.1.0 raised every
  installer to hesape v0.58.0, with which framework v0.56.0's `framework/view`
  does not compile (it converts hesape's `view.Page`, which v0.57.0 widened).
  The module uses nothing newer than v0.56.0, and a feature test now compiles
  it beside `framework/view` so the floor cannot rise past the framework's
  again.

## [0.1.0] - 2026-10-14

The first release: spatie/laravel-webhook-server and laravel-webhook-client for
Arandu, in one package, on hesape/webhook's durable delivery.

### Added

- Sending: `Endpoint`, a tenant's destination with its subscribed events, its
  signer (`SignerArandu` or `SignerHMAC`, webhook-server's DefaultSigner), and a
  signing secret and extra headers sealed with a key derived from the
  application's key. `EndpointService` with `List`, `Find`, `Create` (the secret
  answered once), `Update` (empty headers keep the stored ones), `Delete`,
  `Secret`, `HeaderNames`, `Test` (a `webhook.test` call) and `Deliveries`.
- `Module.Publisher()`: the events outbox delivers each event to the active
  endpoints subscribed to it, through hesape/webhook's Manager.
  `Server.HeaderPrefix` renames the `X-Arandu-` headers.
- `Module.Outgoing()`: webhook-server's `WebhookCall` -- `URL`, `Event`, `UUID`,
  `Payload`, `RawBody`, `UseSecret`, `WithHeaders`, `SignWithHMAC`, `Dispatch`,
  `DispatchIf`, `DispatchUnless`.
- Receiving: `Receiver`, webhook-client's config entry, mounted at
  `ReceivePrefix/<name>`; `SignatureValidator` with `HMAC` (the default) and
  `Arandu` (hesape's scheme, refusing a timestamp more than five minutes away);
  `PreviousSecrets` for a rotation; `Profile`, `Responder`, `StoreHeaders`,
  `OnInvalidSignature`; `Call`, stored with its body as it arrived and processed
  by the receiver's `Processor` on the queue (`ProcessJob`), with its status,
  attempts and last exception. `CallService` with `List`, `Find` and `Process`.
- The scheduled clean `webhook.calls.clean`, webhook-client's
  `delete_after_days`.
- The management routes under `Config.Prefix`, behind `RequireAuth`.
- The actions `EndpointView`, `EndpointList`, `EndpointCreate`,
  `EndpointUpdate`, `EndpointDelete`, `EndpointSecret`, `EndpointTest`,
  `CallView`, `CallList` and `CallProcess`, offered by `Actions()`, and the
  system actions `CallReceive` and `CallClean`.
- The migrations `20261014_0001_create_webhook_server_endpoints` and
  `20261014_0002_create_webhook_client_calls`, beside hesape/webhook's
  `webhook_deliveries`.

