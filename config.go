package webhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/arandu-io/hesape/auth"
)

// The defaults for the optional settings. They are constants rather than
// literals inside Config.withDefaults, so the value a reader finds here is the
// value the package uses.
const (
	// DefaultPrefix is where the management routes are mounted when Config
	// leaves Prefix empty.
	DefaultPrefix = "/webhook"
	// DefaultReceivePrefix is where the receivers are mounted when Config
	// leaves ReceivePrefix empty: a receiver named "billing" answers at
	// /webhooks/billing.
	DefaultReceivePrefix = "/webhooks"
	// DefaultPageSize is how many records one page answers with when Config
	// leaves PageSize at zero.
	DefaultPageSize = 25
	// MaxPageSize is the ceiling PageSize is refused above.
	MaxPageSize = 200
	// DefaultQueue is the queue the deliveries and the processing of received
	// calls travel on.
	DefaultQueue = "webhooks"
	// DefaultUserAgent is what an outgoing call says it is under the default
	// policy.
	DefaultUserAgent = "Arandu-Webhook/1.0"
	// DefaultTimeout is how long an outgoing call may take under the default
	// policy.
	DefaultTimeout = 10 * time.Second
	// DefaultRetention is how long a delivery's record and its attempts are
	// kept.
	DefaultRetention = 30 * 24 * time.Hour
	// DefaultDeleteAfterDays is how old a received call is when the clean
	// removes it, as webhook-client's delete_after_days.
	DefaultDeleteAfterDays = 30
	// DefaultCleanSpec is when the scheduled clean runs: every day at 03:20.
	DefaultCleanSpec = "20 3 * * *"
	// DefaultSignatureHeader is the header a body-HMAC signature travels in,
	// as webhook-server's and webhook-client's signature_header_name.
	DefaultSignatureHeader = "Signature"
	// DefaultMaxBodyBytes is the largest body a receiver reads.
	DefaultMaxBodyBytes = 1 << 20
	// DefaultTries is how many times a received call is processed before it
	// is left failed.
	DefaultTries = 3
	// MaxHeaders is how many extra headers an endpoint may carry.
	MaxHeaders = 20
	// MinSecretBytes is the shortest signing secret accepted.
	MinSecretBytes = 32
)

// Config is what the application passes when it wires this package: the two
// config files of spatie/laravel-webhook-server and laravel-webhook-client,
// as one typed struct. A misspelled key in a map is a setting that silently
// keeps its default; a field that does not exist does not compile.
//
// It names no tenant for the management routes: those sit behind RequireAuth,
// so their tenant is the one the Grant carries, from the session. A Receiver
// names its tenant, because a call from another system arrives with no session
// and its signature is what admits it.
type Config struct {
	// Prefix is the path the management routes are mounted under. Empty means
	// DefaultPrefix.
	Prefix string

	// PageSize is how many records one page answers with. Zero means
	// DefaultPageSize; anything above MaxPageSize is refused.
	PageSize int

	// Key is the application's key (APP_KEY). The endpoints' signing secrets
	// and extra headers are sealed with a key derived from it for this purpose
	// alone. Required, at least MinSecretBytes long.
	Key []byte

	// Server is the sending side.
	Server Server

	// ReceivePrefix is the path every receiver is mounted under. Empty means
	// DefaultReceivePrefix. The application exempts it from the CSRF check,
	// because a call from another system carries no session:
	//
	//	middleware.CSRFProtect(csrf, sessions.IDFromRequest, middleware.CSRFExcept(webhookModule.ReceivePrefix()+"/"))
	ReceivePrefix string

	// Receivers are the receiving side: webhook-client's configs, one per
	// system that calls this application.
	Receivers []Receiver

	// DeleteAfterDays is how old a received call is when the scheduled clean
	// removes it. Zero means DefaultDeleteAfterDays.
	DeleteAfterDays int

	// CleanSpec is the five-field cron expression the clean runs on. Empty
	// means DefaultCleanSpec; "-" schedules none.
	CleanSpec string
}

// Server is the sending side: webhook-server's config.
type Server struct {
	// Queue is the queue deliveries travel on. Empty means DefaultQueue.
	Queue string

	// Policy is how every delivery is made: the attempts and the waits between
	// them, what counts as a failure, the transport's limits. An endpoint may
	// carry its own. Nil means DefaultPolicy, with UserAgent and Timeout below
	// laid over it.
	Policy *Policy

	// UserAgent is sent with every call when Policy is nil. Empty means
	// DefaultUserAgent. Set Policy.UserAgent instead when Policy is set.
	UserAgent string

	// Timeout is how long one call may take when Policy is nil. Zero means
	// DefaultTimeout. Set Policy.Timeout instead when Policy is set.
	Timeout time.Duration

	// Retention is how long a delivery's record and its attempts are kept.
	// Zero means DefaultRetention.
	Retention time.Duration

	// Now is the clock the deliveries read: the signed timestamps, the next
	// attempt, the lease. Nil is time.Now, and a test replaces it.
	Now func() time.Time

	// HeaderPrefix renames the delivery headers, X-Arandu-Signature becoming
	// <HeaderPrefix>-Signature, so a receiver reads the product's name. The
	// signature covers the timestamp, the delivery id and the body, never a
	// header's name, so renaming does not change what is verified. Empty keeps
	// X-Arandu.
	HeaderPrefix string

	// HTTPClient carries the calls. Nil uses hesape's guarded client, with a
	// dialer that also refuses the shared address space (100.64.0.0/10): no
	// call reaches a loopback, private, link-local or shared address, on any
	// hop. A client given here keeps its own transport and with it its own
	// answer to where a call may connect, which is what a test that delivers
	// to a local server needs.
	HTTPClient *http.Client

	// Events is the list an endpoint may subscribe to. Empty accepts any
	// event name.
	Events []string

	// AllowEmptySubscription lets an endpoint subscribe to no event: the
	// events outbox then sends it nothing, while Send, the test call and a
	// redelivery still reach it. False refuses an endpoint with no event, as
	// before.
	AllowEmptySubscription bool

	// Secrets are named signing secrets for calls built with Outgoing, as
	// webhook-server's useSecret. Each is at least MinSecretBytes long.
	Secrets map[string]string
}

// Receiver is one system that calls this application: webhook-client's
// config entry, mounted at ReceivePrefix + "/" + Name unless Path or Mount
// says otherwise.
//
// A receiver is static -- one Tenant and one Secret from the configuration --
// or dynamic: Resolve finds the record a request is addressed to, and the
// record says whose call it is and which secrets sign it. Either way nothing
// in the request chooses the tenant. A path parameter only says which record
// to look for, and the signature checked against that record's secrets is
// what admits the call.
type Receiver struct {
	// Name identifies the receiver, its route and its calls: lowercase
	// letters, digits and dashes.
	Name string

	// Path is where the receiver answers under ReceivePrefix, and may carry
	// path parameters for Resolve to read with r.PathValue: "cielo/{token}"
	// answers at /webhooks/cielo/{token}. Empty means Name.
	Path string

	// Mount is an absolute path the receiver answers at instead, outside
	// ReceivePrefix, for an address that is already published:
	// "/integracoes/lpr/{org}/{key}". It cannot be under /_arandu. The
	// application exempts it from the CSRF check too; ReceivePaths lists
	// what to exempt.
	Mount string

	// Tenant is whose calls these are, for a static receiver. It comes from
	// the application's configuration, never from the request. A receiver
	// with Resolve leaves it empty.
	Tenant string

	// Resolve finds the record a request is addressed to, before anything is
	// read of its body: its tenant, the secrets that sign its calls, a
	// validator of its own when it needs one, and a reference the call keeps
	// for the processor. An error answers Statuses.Unresolved, or
	// Statuses.Unavailable when it wraps ErrReceiverUnavailable.
	Resolve Resolver

	// Methods are the HTTP methods accepted. Empty means POST.
	Methods []string

	// Secret is the signing secret the sender shares; PreviousSecrets are
	// still accepted while the sender rotates. Required unless Validator is
	// the application's own.
	Secret          string
	PreviousSecrets []string

	// Validator checks the signature. Nil means HMAC{Header:
	// DefaultSignatureHeader}, webhook-client's DefaultSignatureValidator.
	Validator SignatureValidator

	// Profile decides whether a valid call is stored and processed. Nil
	// processes every call.
	Profile Profile

	// Respond answers the sender. Nil answers 200 {"message":"ok"}.
	Respond Responder

	// StoreHeaders are the request headers kept with the call; "*" keeps
	// them all. Empty keeps none.
	StoreHeaders []string

	// Process handles a stored call on the queue: webhook-client's
	// process_webhook_job. Required unless ProcessSync is set.
	Process Processor

	// ProcessSync handles a stored call before the sender is answered, and
	// its result is the answer: the status and the body. The call is still
	// stored, and its outcome kept on it. Set it instead of Process for a
	// sender that needs to know what became of its call.
	ProcessSync SyncProcessor

	// ReencodeForm takes a form-encoded call whose raw body is empty -- read
	// already by something that parsed the form -- as the form encoded
	// again.
	ReencodeForm bool

	// Statuses are what each refusal answers. A zero field keeps its
	// default.
	Statuses Statuses

	// URL is how the address a call arrived at is kept on it. Empty keeps
	// the full address of a receiver whose route has no parameter, and only
	// the route -- its parameters as {name}, no query -- of one whose route
	// has, because a path parameter is often a bearer token.
	URL URLMode

	// Tries is how many times a call is processed before it stays failed.
	// Zero means DefaultTries.
	Tries int

	// MaxBodyBytes is the largest body read. Zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64

	// OnInvalidSignature is called when a request fails the signature check,
	// as webhook-client's InvalidWebhookSignatureEvent. Optional.
	OnInvalidSignature func(r *http.Request, receiver string)
}

var (
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	headerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
)

// Validate reports what the configuration cannot be used with. It is called
// by New, so a setting that cannot work fails where it is wired rather than on
// the first request that needed it.
func (c Config) Validate() error {
	for _, prefix := range []struct{ field, value string }{{"Prefix", c.Prefix}, {"ReceivePrefix", c.ReceivePrefix}} {
		if prefix.value == "" {
			continue
		}
		if prefix.value[0] != '/' || prefix.value == "/" || strings.HasSuffix(prefix.value, "/") {
			return fmt.Errorf("webhook: Config.%s is %q and has to start with / and not end with one", prefix.field, prefix.value)
		}
		if err := validateRoutePrefix(prefix.value); err != nil {
			return err
		}
	}
	if c.PageSize < 0 || c.PageSize > MaxPageSize {
		return fmt.Errorf("webhook: Config.PageSize is %d, and has to be between 0 and %d, where 0 means %d", c.PageSize, MaxPageSize, DefaultPageSize)
	}
	if len(c.Key) < MinSecretBytes {
		return fmt.Errorf("webhook: Config.Key has %d bytes and needs at least %d: pass the application's key", len(c.Key), MinSecretBytes)
	}
	if c.DeleteAfterDays < 0 {
		return errors.New("webhook: Config.DeleteAfterDays cannot be negative")
	}
	if c.Server.Timeout < 0 || c.Server.Retention < 0 {
		return errors.New("webhook: Config.Server.Timeout and Retention cannot be negative")
	}
	if c.Server.Policy != nil {
		if c.Server.Timeout != 0 || c.Server.UserAgent != "" {
			return errors.New("webhook: Config.Server.Timeout and UserAgent apply only without a Policy; set Policy.Timeout and Policy.UserAgent instead")
		}
		if err := c.Server.Policy.Validate(); err != nil {
			return fmt.Errorf("webhook: Config.Server.Policy: %w", err)
		}
	}
	if p := c.Server.HeaderPrefix; p != "" && (!headerPattern.MatchString(p) || strings.EqualFold(p, "X-Arandu")) {
		return fmt.Errorf("webhook: Config.Server.HeaderPrefix %q is not a header name such as X-Acme", p)
	}
	for name, secret := range c.Server.Secrets {
		if !namePattern.MatchString(name) {
			return fmt.Errorf("webhook: Config.Server.Secrets has the name %q: use lowercase letters, digits and dashes", name)
		}
		if len(secret) < MinSecretBytes {
			return fmt.Errorf("webhook: Config.Server.Secrets[%q] has %d bytes and needs at least %d", name, len(secret), MinSecretBytes)
		}
	}
	seen := map[string]bool{}
	for i, r := range c.Receivers {
		if err := r.validate(); err != nil {
			return fmt.Errorf("webhook: Config.Receivers[%d]: %w", i, err)
		}
		if seen[r.Name] {
			return fmt.Errorf("webhook: Config.Receivers has %q twice", r.Name)
		}
		seen[r.Name] = true
	}
	return validateReceiverRoutes(c)
}

// reservedPrefix is the namespace the framework keeps for itself.
const reservedPrefix = "/_arandu"

// validateReceiverRoutes registers every receiver's pattern on a throwaway
// mux, which refuses a pattern it cannot parse and two that conflict -- by
// panicking, which is turned into the error New promises.
func validateReceiverRoutes(c Config) (err error) {
	prefix := c.ReceivePrefix
	if prefix == "" {
		prefix = DefaultReceivePrefix
	}
	current := ""
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("webhook: the receiver %q cannot be registered at its path: %v", current, recovered)
		}
	}()
	mux := http.NewServeMux()
	for _, r := range c.Receivers {
		current = r.Name
		methods := r.Methods
		if len(methods) == 0 {
			methods = []string{http.MethodPost}
		}
		for _, method := range methods {
			mux.Handle(strings.ToUpper(method)+" "+r.route(prefix), http.NotFoundHandler())
		}
	}
	return nil
}

// route is the path the receiver answers at.
func (r Receiver) route(receivePrefix string) string {
	switch {
	case r.Mount != "":
		return r.Mount
	case r.Path != "":
		return receivePrefix + "/" + r.Path
	}
	return receivePrefix + "/" + r.Name
}

// URLMode is how a received call keeps the address it arrived at.
type URLMode string

const (
	// URLFull keeps the scheme, host, path and query as they arrived.
	URLFull URLMode = "full"
	// URLRoute keeps the scheme, host and the receiver's route, its path
	// parameters written as {name} and no query: what was called, without
	// the values a path or a query carried.
	URLRoute URLMode = "route"
	// URLNone keeps no address.
	URLNone URLMode = "none"
)

// Statuses are what a receiver answers each refusal with. A zero field keeps
// its default, which is what a receiver answered before it could be chosen.
type Statuses struct {
	// Unresolved is a request Resolve found no record for. Default 404.
	Unresolved int
	// InvalidSignature is a call whose signature does not check. Default 403.
	InvalidSignature int
	// EmptyBody is a call with no body. Zero accepts one.
	EmptyBody int
	// TooLarge is a body above MaxBodyBytes. Default 413.
	TooLarge int
	// BadRequest is a body that could not be read. Default 400.
	BadRequest int
	// Unavailable is a Resolve that answered ErrReceiverUnavailable. Default
	// 503.
	Unavailable int
	// Failed is a ProcessSync that answered an error. Default 500.
	Failed int
}

// The default statuses of a receiver's refusals.
const (
	DefaultUnresolvedStatus       = http.StatusNotFound
	DefaultInvalidSignatureStatus = http.StatusForbidden
	DefaultTooLargeStatus         = http.StatusRequestEntityTooLarge
	DefaultBadRequestStatus       = http.StatusBadRequest
	DefaultUnavailableStatus      = http.StatusServiceUnavailable
	DefaultFailedStatus           = http.StatusInternalServerError
)

func (s Statuses) withDefaults() Statuses {
	pick := func(value, fallback int) int {
		if value == 0 {
			return fallback
		}
		return value
	}
	s.Unresolved = pick(s.Unresolved, DefaultUnresolvedStatus)
	s.InvalidSignature = pick(s.InvalidSignature, DefaultInvalidSignatureStatus)
	s.TooLarge = pick(s.TooLarge, DefaultTooLargeStatus)
	s.BadRequest = pick(s.BadRequest, DefaultBadRequestStatus)
	s.Unavailable = pick(s.Unavailable, DefaultUnavailableStatus)
	s.Failed = pick(s.Failed, DefaultFailedStatus)
	return s
}

func (r Receiver) validate() error {
	if !namePattern.MatchString(r.Name) {
		return fmt.Errorf("Name %q: use lowercase letters, digits and dashes", r.Name)
	}
	if r.Resolve == nil && !auth.ValidTenant(r.Tenant) {
		return fmt.Errorf("receiver %q has no valid Tenant: name whose calls these are, or Resolve them", r.Name)
	}
	if r.Resolve != nil && r.Tenant != "" {
		return fmt.Errorf("receiver %q has a Tenant and a Resolve: the tenant is the resolved record's", r.Name)
	}
	if r.Path != "" && r.Mount != "" {
		return fmt.Errorf("receiver %q has a Path and a Mount: it answers at one address", r.Name)
	}
	if r.Path != "" && (strings.HasPrefix(r.Path, "/") || strings.HasSuffix(r.Path, "/")) {
		return fmt.Errorf("receiver %q: Path %q is relative to ReceivePrefix, with no slash at either end", r.Name, r.Path)
	}
	if r.Mount != "" && (!strings.HasPrefix(r.Mount, "/") || strings.HasSuffix(r.Mount, "/") ||
		r.Mount == reservedPrefix || strings.HasPrefix(r.Mount, reservedPrefix+"/")) {
		return fmt.Errorf("receiver %q: Mount %q is an absolute path, not ending in / and not under %s", r.Name, r.Mount, reservedPrefix)
	}
	switch r.URL {
	case "", URLFull, URLRoute, URLNone:
	default:
		return fmt.Errorf("receiver %q: URL %q is not URLFull, URLRoute or URLNone", r.Name, r.URL)
	}
	for _, status := range []int{r.Statuses.Unresolved, r.Statuses.InvalidSignature, r.Statuses.EmptyBody,
		r.Statuses.TooLarge, r.Statuses.Unavailable, r.Statuses.Failed, r.Statuses.BadRequest} {
		if status != 0 && (status < 400 || status > 599) {
			return fmt.Errorf("receiver %q: a refusal answers a 4xx or 5xx status, not %d", r.Name, status)
		}
	}
	for _, m := range r.Methods {
		switch strings.ToUpper(m) {
		case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return fmt.Errorf("receiver %q: %q is not a method a webhook arrives with", r.Name, m)
		}
	}
	if r.Resolve == nil && r.Validator == nil && len(r.Secret) == 0 {
		return fmt.Errorf("receiver %q has no Secret: a call nobody signed is not accepted", r.Name)
	}
	if (r.Process == nil) == (r.ProcessSync == nil) {
		return fmt.Errorf("receiver %q needs one of Process and ProcessSync: name what handles its calls", r.Name)
	}
	if r.ProcessSync != nil && r.Respond != nil {
		return fmt.Errorf("receiver %q has a Respond and a ProcessSync: the processor's result is the answer", r.Name)
	}
	if r.Tries < 0 || r.MaxBodyBytes < 0 {
		return fmt.Errorf("receiver %q: Tries and MaxBodyBytes cannot be negative", r.Name)
	}
	return nil
}

// validateRoutePrefix asks the standard library to parse the exact patterns
// the module will register. Its parser is not exported and reports invalid
// patterns by panic, so the throwaway mux turns that boot-time panic into the
// configuration error New promises.
func validateRoutePrefix(prefix string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("webhook: the prefix %q cannot be registered as a route path", prefix)
		}
	}()

	handler := http.NotFoundHandler()
	mux := http.NewServeMux()
	mux.Handle(http.MethodGet+" "+prefix+"/endpoints/{id}", handler)
	mux.Handle(http.MethodPost+" "+prefix+"/{name}", handler)
	return nil
}

// withDefaults returns the configuration with the optional fields filled in.
// It runs after Validate and never before.
func (c Config) withDefaults() Config {
	if c.Prefix == "" {
		c.Prefix = DefaultPrefix
	}
	if c.ReceivePrefix == "" {
		c.ReceivePrefix = DefaultReceivePrefix
	}
	if c.PageSize == 0 {
		c.PageSize = DefaultPageSize
	}
	if c.DeleteAfterDays == 0 {
		c.DeleteAfterDays = DefaultDeleteAfterDays
	}
	if c.CleanSpec == "" {
		c.CleanSpec = DefaultCleanSpec
	}
	if c.Server.Queue == "" {
		c.Server.Queue = DefaultQueue
	}
	if c.Server.Policy == nil {
		policy := DefaultPolicy()
		if c.Server.UserAgent != "" {
			policy.UserAgent = c.Server.UserAgent
		}
		if c.Server.Timeout != 0 {
			policy.Timeout = c.Server.Timeout
		}
		c.Server.Policy = &policy
	} else {
		policy := c.Server.Policy.clone()
		c.Server.Policy = &policy
	}
	if c.Server.Retention == 0 {
		c.Server.Retention = DefaultRetention
	}
	if c.Server.Now == nil {
		c.Server.Now = time.Now
	}
	receivers := make([]Receiver, len(c.Receivers))
	for i, r := range c.Receivers {
		if len(r.Methods) == 0 {
			r.Methods = []string{http.MethodPost}
		}
		for j, m := range r.Methods {
			r.Methods[j] = strings.ToUpper(m)
		}
		if r.Validator == nil {
			r.Validator = HMAC{Header: DefaultSignatureHeader}
		}
		if r.Profile == nil {
			r.Profile = ProcessEverything{}
		}
		if r.Respond == nil && r.ProcessSync == nil {
			r.Respond = RespondOK{}
		}
		r.Statuses = r.Statuses.withDefaults()
		if r.URL == "" {
			r.URL = URLFull
			if strings.Contains(r.route(c.ReceivePrefix), "{") {
				r.URL = URLRoute
			}
		}
		if r.Tries == 0 {
			r.Tries = DefaultTries
		}
		if r.MaxBodyBytes == 0 {
			r.MaxBodyBytes = DefaultMaxBodyBytes
		}
		receivers[i] = r
	}
	c.Receivers = receivers
	return c
}

// The limits a Policy is refused beyond. They keep a policy written by a
// person, or stored on an endpoint, from asking for something the engine
// should not do.
const (
	// MaxTries is the most attempts one delivery may be given.
	MaxTries = 20
	// MaxBackoff is the longest wait between two attempts.
	MaxBackoff = 7 * 24 * time.Hour
	// MaxRedirects is the most redirects a delivery may follow.
	MaxRedirects = 10
	// MaxTimeout is the longest one attempt may take.
	MaxTimeout = 2 * time.Minute
	// MaxRequestBytes is the largest body a delivery may carry.
	MaxRequestBytes = 1 << 20
	// MaxResponseBytes is the most of an answer an attempt reads.
	MaxResponseBytes = 1 << 20
)

// RetryMode says which failed attempts are tried again.
type RetryMode string

const (
	// RetryTransient tries again what another attempt may fix -- a transport
	// error, 408, 425, 429 and the 5xx -- and gives up at once on every other
	// answer, on an address that is refused and on a body too large. It is
	// the default.
	RetryTransient RetryMode = "transient"
	// RetryEveryFailure tries again every failed attempt, whatever it was,
	// until the tries are spent: any answer outside 2xx is a failure like any
	// other.
	RetryEveryFailure RetryMode = "every-failure"
)

// Policy is how a delivery is made. It is set on Server for every endpoint,
// and an endpoint may carry its own. Tries and Backoff are frozen on each
// delivery when it is recorded, so changing a policy neither revives a
// delivery that gave up nor shortens one already waiting; the rest is read at
// every attempt.
//
// A Policy is used as written: a zero field means zero, not a default. Start
// from DefaultPolicy to change one thing.
type Policy struct {
	// Tries is how many attempts a delivery gets, the first included.
	Tries int
	// Backoff is the wait before each attempt after the first: Backoff[0]
	// before the second, Backoff[1] before the third. When it is shorter than
	// Tries-1 its last wait is repeated. There is no jitter: the next attempt
	// is written on the delivery, so two workers never race for one.
	Backoff []time.Duration
	// Retry is which failures are tried again. Empty means RetryTransient.
	Retry RetryMode
	// HonorRetryAfter waits as long as the receiver's Retry-After asks before
	// the next attempt, when that is longer than Backoff says.
	HonorRetryAfter bool
	// HTTPSOnly refuses an address that is not https, at the endpoint's form
	// and at every attempt.
	HTTPSOnly bool
	// MaxRedirects is how many redirects an attempt follows; 0 follows none,
	// and the redirect itself is then the answer, a failure.
	MaxRedirects int
	// MaxRequestBytes is the largest body a delivery may be recorded with.
	MaxRequestBytes int64
	// MaxResponseBytes is how much of an answer an attempt reads; the rest is
	// left unread, and the answer's status decides the attempt.
	MaxResponseBytes int64
	// Timeout is how long one attempt may take, the answer read included.
	Timeout time.Duration
	// UserAgent is sent with every attempt. Empty sends none of ours: Go's
	// client then says what it is.
	UserAgent string
	// DisableAfter turns a stored endpoint off once this many of its
	// deliveries in a row gave up, and records why. A delivered one resets
	// the count. 0 never turns one off.
	DisableAfter int
}

// DefaultPolicy is the policy a delivery gets when nobody chose one: 5
// attempts, waiting 5 s, 30 s, 2 min and 10 min between them, the receiver's
// Retry-After honored, 408, 425, 429 and the 5xx tried again and every other
// answer final, at most 5 redirects, http or https, a body of up to 1 MiB, the
// first 1 MiB of an answer read, 10 s per attempt, and DefaultUserAgent.
func DefaultPolicy() Policy {
	return Policy{
		Tries:            5,
		Backoff:          []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute},
		Retry:            RetryTransient,
		HonorRetryAfter:  true,
		MaxRedirects:     5,
		MaxRequestBytes:  MaxRequestBytes,
		MaxResponseBytes: MaxResponseBytes,
		Timeout:          DefaultTimeout,
		UserAgent:        DefaultUserAgent,
	}
}

// Validate reports what the policy cannot be used with.
func (p Policy) Validate() error {
	switch {
	case p.Tries < 1 || p.Tries > MaxTries:
		return fmt.Errorf("Tries is %d, and has to be between 1 and %d", p.Tries, MaxTries)
	case len(p.Backoff) > MaxTries:
		return fmt.Errorf("Backoff has %d waits, and at most %d are used", len(p.Backoff), MaxTries)
	case p.Tries > 1 && len(p.Backoff) == 0:
		return errors.New("Backoff is empty, and a policy of more than one try needs the wait between them")
	case p.Retry != "" && p.Retry != RetryTransient && p.Retry != RetryEveryFailure:
		return fmt.Errorf("Retry %q is not RetryTransient or RetryEveryFailure", p.Retry)
	case p.MaxRedirects < 0 || p.MaxRedirects > MaxRedirects:
		return fmt.Errorf("MaxRedirects is %d, and has to be between 0 and %d", p.MaxRedirects, MaxRedirects)
	case p.MaxRequestBytes < 1 || p.MaxRequestBytes > MaxRequestBytes:
		return fmt.Errorf("MaxRequestBytes is %d, and has to be between 1 and %d", p.MaxRequestBytes, MaxRequestBytes)
	case p.MaxResponseBytes < 0 || p.MaxResponseBytes > MaxResponseBytes:
		return fmt.Errorf("MaxResponseBytes is %d, and has to be between 0 and %d", p.MaxResponseBytes, MaxResponseBytes)
	case p.Timeout <= 0 || p.Timeout > MaxTimeout:
		return fmt.Errorf("Timeout is %s, and has to be above zero and at most %s", p.Timeout, MaxTimeout)
	case p.DisableAfter < 0:
		return errors.New("DisableAfter cannot be negative")
	}
	for _, wait := range p.Backoff {
		if wait < 0 || wait > MaxBackoff {
			return fmt.Errorf("Backoff has the wait %s, and each has to be between 0 and %s", wait, MaxBackoff)
		}
	}
	for i := 0; i < len(p.UserAgent); i++ {
		if p.UserAgent[i] < ' ' || p.UserAgent[i] == 0x7f {
			return errors.New("UserAgent carries a control character")
		}
	}
	return nil
}

// plan is the waits before each attempt after the first, one per retry: the
// Backoff, with its last wait repeated up to Tries-1.
func (p Policy) plan() []time.Duration {
	out := make([]time.Duration, 0, p.Tries)
	for i := 1; i < p.Tries; i++ {
		wait := time.Duration(0)
		switch {
		case i-1 < len(p.Backoff):
			wait = p.Backoff[i-1]
		case len(p.Backoff) > 0:
			wait = p.Backoff[len(p.Backoff)-1]
		}
		out = append(out, wait)
	}
	return out
}

func (p Policy) clone() Policy {
	p.Backoff = append([]time.Duration(nil), p.Backoff...)
	return p
}

// policyJSON is a Policy as an endpoint stores it, durations in milliseconds.
type policyJSON struct {
	Tries            int       `json:"tries"`
	Backoff          []int64   `json:"backoff_ms"`
	Retry            RetryMode `json:"retry"`
	HonorRetryAfter  bool      `json:"honor_retry_after"`
	HTTPSOnly        bool      `json:"https_only"`
	MaxRedirects     int       `json:"max_redirects"`
	MaxRequestBytes  int64     `json:"max_request_bytes"`
	MaxResponseBytes int64     `json:"max_response_bytes"`
	TimeoutMS        int64     `json:"timeout_ms"`
	UserAgent        string    `json:"user_agent"`
	DisableAfter     int       `json:"disable_after"`
}

func encodePolicy(p *Policy) (string, error) {
	if p == nil {
		return "", nil
	}
	out := policyJSON{
		Tries: p.Tries, Retry: p.Retry, HonorRetryAfter: p.HonorRetryAfter, HTTPSOnly: p.HTTPSOnly,
		MaxRedirects: p.MaxRedirects, MaxRequestBytes: p.MaxRequestBytes, MaxResponseBytes: p.MaxResponseBytes,
		TimeoutMS: p.Timeout.Milliseconds(), UserAgent: p.UserAgent, DisableAfter: p.DisableAfter,
	}
	for _, wait := range p.Backoff {
		out.Backoff = append(out.Backoff, wait.Milliseconds())
	}
	encoded, err := json.Marshal(out)
	return string(encoded), err
}

func decodePolicy(text string) (*Policy, error) {
	if text == "" {
		return nil, nil
	}
	var in policyJSON
	if err := json.Unmarshal([]byte(text), &in); err != nil {
		return nil, fmt.Errorf("webhook: the endpoint's policy is not readable: %w", err)
	}
	p := Policy{
		Tries: in.Tries, Retry: in.Retry, HonorRetryAfter: in.HonorRetryAfter, HTTPSOnly: in.HTTPSOnly,
		MaxRedirects: in.MaxRedirects, MaxRequestBytes: in.MaxRequestBytes, MaxResponseBytes: in.MaxResponseBytes,
		Timeout: time.Duration(in.TimeoutMS) * time.Millisecond, UserAgent: in.UserAgent, DisableAfter: in.DisableAfter,
	}
	for _, ms := range in.Backoff {
		p.Backoff = append(p.Backoff, time.Duration(ms)*time.Millisecond)
	}
	return &p, nil
}
