# Changelog

Everything worth knowing about a release of Arandu Webhook is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

## [0.2.0] - 2026-10-14

The module owns its outbound delivery. hesape/webhook's Manager is no longer
underneath: the deliveries, their attempts, their retries and the transport are
this module's, built from hesape's pieces (the guarded HTTP client, the queue,
`webhook.Sign` and `Verify`, the encrypter, the events outbox).

### Added

- A delivery engine of its own. `Delivery` is a record on the module's table
  `webhook_server_deliveries`: the body frozen with its SHA-256, the extra
  headers sealed, the number of attempts and the waits between them frozen
  when it is recorded, its status (`pending`, `processing`, `delivered`,
  `failed`), the next attempt, the receiver's last answer, and a claim with a
  lease so two workers, or a worker and a redelivery, never send one attempt
  twice. One event reaches one endpoint once (unique on tenant, event and
  endpoint). Each attempt is a `DeliverJob` (`webhook.server.deliver`) queued
  in the same transaction as the row; each attempt is signed when it is made.
- `DeliveryAttempt`, on `webhook_server_delivery_attempts`: every attempt's
  number, trigger (`AttemptScheduled` or `AttemptManual`), outcome, status,
  failure code, the first 500 characters of the answer, duration and signed
  timestamp.
- Dialects per endpoint: `DialectArandu` (the default, as before),
  `DialectHMAC` (webhook-server's DefaultSigner, with or without the Arandu
  headers: `EndpointRequest.WithoutAranduHeaders`, `Endpoint.AranduHeaders`),
  and `DialectStandardWebhooks` (`Webhook-Id`, `Webhook-Timestamp`,
  `Webhook-Signature` with one `v1,` entry per secret still signing, newest
  first). `SignStandard`, `StandardSecretPrefix`, `ErrStandardSecret` and the
  `StandardHeader*` names. `Outgoing.WithoutAranduHeaders`.
- `Policy`, on `Server.Policy` and per endpoint (`EndpointRequest.Policy`,
  `ResetPolicy`): tries and backoff, `RetryTransient` or `RetryEveryFailure`,
  `HonorRetryAfter`, `HTTPSOnly`, `MaxRedirects`, request and response caps,
  timeout, `UserAgent` (empty sends Go's own), and `DisableAfter`, which turns
  an endpoint off after that many of its deliveries in a row gave up
  (`DisabledByFailures`). `DefaultPolicy` is v0.1.0's behaviour.
  `Server.Now` is the clock the deliveries read.
- `Module.Send`: one `Message` (`ID`, `EventID`, `Event`, `Body`) to one
  stored endpoint, the id and the body sent exactly as given, under a Grant
  carrying `DeliveryDispatch`.
- `EndpointService.Rotate` (the previous secret keeps signing until it
  retires, one already retiring is revoked), `Import` (`ImportRequest` and
  `PreviousSecret`: an endpoint stored with the id and secrets it already
  has), `Enable` and `Disable` (deliveries wait while an endpoint is off and
  go when it is on again), `Delivery`, `Attempts` and `Redeliver` (the same id
  and body, a new timestamp and signature). `ErrEndpointExists`,
  `ErrDeliveryInProgress`, `ErrNotRedeliverable`, `ErrDeliveryIDTaken`,
  `ErrInvalidMessage`, `ErrPayloadTooLarge`, `ErrHTTPSRequired`, the
  `Failure*` codes and `DefaultRotationOverlap`.
- The routes `POST …/endpoints/{id}/rotate`, `…/enable`, `…/disable`,
  `GET …/deliveries/{id}`, `GET …/deliveries/{id}/attempts` and
  `POST …/deliveries/{id}/redeliver`.
- Every management act stores an event in the application's outbox, in the
  same transaction: `EventEndpointCreated`, `EventEndpointUpdated` (before and
  after), `EventEndpointDeleted`, `EventEndpointEnabled`,
  `EventEndpointDisabled` (also when the engine turns one off),
  `EventEndpointImported`, `EventSecretRevealed`, `EventSecretRotated`,
  `EventEndpointTested`, `EventDeliveryRedelivered` and
  `EventCallReprocessed`. arandu-activitylog's `EventRecorder` writes them as
  entries; the module's Publisher does not deliver them to endpoints.
- The actions `EndpointRotate` and `DeliveryRedeliver`, offered by
  `Actions()`; `EndpointImport`, allowed to a subject that carries it and not
  offered; and the system actions `DeliveryDispatch` (the value of
  hesape/webhook's `ActionDispatch`) and `DeliveryClean`.
- The scheduled clean `webhook.deliveries.clean`, per tenant, removing the
  settled deliveries and the attempts older than `Server.Retention`
  (`DefaultRetention`, 30 days).
- The migrations `20261014_0003_add_dialect_and_policy_to_webhook_server_endpoints`,
  `20261014_0004_create_webhook_server_deliveries` and
  `20261014_0005_create_webhook_server_delivery_attempts`.

### Changed

- The deliveries are made by this module and recorded in
  `webhook_server_deliveries`. `Delivery`, `Deliveries(db)` and
  `EndpointService.Deliveries` read that table; hesape/webhook's
  `webhook_deliveries` is no longer written, read or migrated.
- `EndpointService.Test` answers the test's `Delivery`, and its route answers
  it with 202.
- Without `Server.HTTPClient`, the transport also refuses the shared address
  space (100.64.0.0/10) and goes through no proxy from the environment.
- A new secret is `whsec_` and the standard base64 of 32 bytes, which every
  dialect signs with; secrets already stored keep signing as they are.
- An endpoint turned off keeps its deliveries waiting rather than sending
  them; a deleted endpoint's deliveries fail as `endpoint_deleted`.
- An answer is read up to `Policy.MaxResponseBytes` (1 MiB by default) and the
  rest left unread, instead of failing a delivery whose answer was larger than
  32 MiB.

### Removed

- `Module.Manager`: there is no hesape/webhook Manager underneath any more.

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

