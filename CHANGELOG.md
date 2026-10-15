# Changelog

Everything worth knowing about a release of Arandu Webhook is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

## [0.4.0] - 2026-10-15

What the first application to move its webhooks into the module found
missing.

### Added

- `ImportRequest.ConsecutiveFailures`, `DisabledAt` and `DisabledReason`, so an
  imported endpoint keeps its count towards `DisableAfter` and why it was
  turned off. `DisabledAt` and `DisabledReason` come together and need
  `Active` false; a reason is one line of at most `MaxDisabledReason` (64)
  bytes.
- `EndpointService.DisableWithReason`: turns an endpoint off keeping the
  reason in `DisabledReason`, with `DisabledAt`, and in the
  `webhook.endpoint.disabled` event. `POST …/endpoints/{id}/disable` takes it
  as `reason`.
- `Server.AllowEmptySubscription`: an endpoint may subscribe to no event. The
  events outbox sends it nothing; `Send`, the test call and a redelivery
  still reach it. Without it an endpoint with no event is refused, as before.
- `Call.RemoteAddr` and `Call.HeadersSHA256`, kept on every received call;
  `HeadersDigest`, the canonical SHA-256 of a request's headers; and
  `Call.ReceivedHeaders`, every header of the request, for a `SyncProcessor`
  -- including the ones `StoreHeaders` does not keep.
- `Receiver.URL` (`URLMode`: `URLFull`, `URLRoute`, `URLNone`): how a call
  keeps the address it arrived at.
- `Receiver.RefusalBody` (`RefusalMode`): `RefusalText`, the default, answers
  a receiver's refusals through the router with the status's sentence, as
  before; `RefusalEmpty` answers every refusal of the receiver -- unresolved,
  invalid signature, empty, too large, unreadable, unavailable, failed -- with
  the status alone, exactly what a handler that only calls `WriteHeader`
  answers.
- The migration
  `20261015_0007_add_remote_addr_and_headers_digest_to_webhook_client_calls`.

### Changed

- A receiver whose `Path` or `Mount` has a path parameter keeps only its route
  on the call -- `https://host/webhooks/cielo/{token}`, no query -- because the
  parameter is often a bearer token. `URL: webhook.URLFull` keeps the whole
  address. Calls stored before stay as they are.
- `webhook.calls.clean` and `webhook.deliveries.clean` are one global pass
  over every tenant with rows in their table, each tenant under a Grant of its
  own, instead of a task per tenant the scheduler lists: a platform tenant, or
  a tenant a resolver named, is cleaned too.

### Fixed

- `ImportRequest.CreatedAt` is kept: the insert no longer stamps the moment of
  the import over it.


## [0.3.0] - 2026-10-15

The receiving side takes calls addressed to records of the application, at
the addresses those calls already use.

### Added

- Dynamic receivers. `Receiver.Resolve` (a `Resolver`, `ResolverFunc`) finds
  the record a request is addressed to from its path, before the body is read:
  a `Resolution` with the record's tenant, its `Secret` and `PreviousSecrets`,
  an optional `Validator` of its own and a `Reference` the call keeps as
  `Call.Reference`. The tenant is the record's: a path parameter only says
  which record to look for, and the signature checked against its secrets
  admits the call. `ErrReceiverUnavailable` answers 503.
- `Receiver.Path`, a pattern under `ReceivePrefix` with path parameters
  (`"cielo/{token}"`), and `Receiver.Mount`, an absolute address outside it
  (`"/integracoes/lpr/{org}/{key}"`), so a receiver keeps a URL already
  published. `Module.ReceivePaths` lists the prefixes to exempt from CSRF.
- `HeaderSecret{Header}`, a shared secret sent as it is, compared in constant
  time with every accepted secret, refusing every call when there is none and
  checked before the body is read; and `StandardWebhooks{Tolerance, Now}`, the
  Standard Webhooks scheme, accepting any `v1` signature under the current or a
  previous secret within five minutes.
- `Receiver.Statuses` (`Statuses`): what an unresolved request, an invalid
  signature, an empty body, a body too large, a body that cannot be read, an
  unavailable resolver and a failed synchronous processing answer, with the
  defaults `DefaultUnresolvedStatus`, `DefaultInvalidSignatureStatus`,
  `DefaultTooLargeStatus`, `DefaultBadRequestStatus`,
  `DefaultUnavailableStatus` and `DefaultFailedStatus`. An empty body is still
  accepted unless `EmptyBody` is set.
- `Receiver.ReencodeForm`: a form whose raw body was already read is taken as
  the form encoded again.
- `Receiver.ProcessSync` (`SyncProcessor`, `SyncProcessorFunc`,
  `ProcessResult`): the call is stored, processed before the sender is
  answered, and the processor's status and body are the answer; the outcome is
  kept on the call, and `CallService.Process` processes it again on the queue.
- The migration `20261015_0006_add_reference_to_webhook_client_calls`.

### Changed

- A body that cannot be read answers 400 (`Statuses.BadRequest`) instead of
  500.
- `webhook.calls.clean` runs per tenant, as `webhook.deliveries.clean` does,
  because a receiver with `Resolve` takes calls for any tenant.
- A received call's resource answers its `reference`.


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
  go when it is on again; turning one on from `Update` does the same),
  `Delivery`, `Attempts` and `Redeliver` (the same id and body, a new timestamp
  and signature). An import keeps at most `MaxPreviousSecrets`. `ErrEndpointExists`,
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

