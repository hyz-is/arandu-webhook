package webhook

import (
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
	// DefaultUserAgent is what an outgoing call says it is.
	DefaultUserAgent = "Arandu-Webhook/1.0"
	// DefaultTimeout is how long an outgoing call may take.
	DefaultTimeout = 10 * time.Second
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

	// UserAgent is sent with every call. Empty means DefaultUserAgent.
	UserAgent string

	// Timeout is how long one call may take. Zero means DefaultTimeout.
	Timeout time.Duration

	// Retention is how long a delivery's record is kept. Zero means
	// hesape/webhook's DefaultRetention.
	Retention time.Duration

	// HeaderPrefix renames the delivery headers, X-Arandu-Signature becoming
	// <HeaderPrefix>-Signature, so a receiver reads the product's name. The
	// signature covers the timestamp, the delivery id and the body, never a
	// header's name, so renaming does not change what is verified. Empty keeps
	// X-Arandu.
	HeaderPrefix string

	// HTTPClient carries the calls. Nil uses hesape's client, which refuses
	// private and loopback addresses on every hop.
	HTTPClient *http.Client

	// Events is the list an endpoint may subscribe to. Empty accepts any
	// event name.
	Events []string

	// Secrets are named signing secrets for calls built with Outgoing, as
	// webhook-server's useSecret. Each is at least MinSecretBytes long.
	Secrets map[string]string
}

// Receiver is one system that calls this application: webhook-client's
// config entry, mounted at ReceivePrefix + "/" + Name.
type Receiver struct {
	// Name identifies the receiver, its route and its calls: lowercase
	// letters, digits and dashes.
	Name string

	// Tenant is whose calls these are. It comes from the application's
	// configuration, never from the request.
	Tenant string

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
	// process_webhook_job. Required.
	Process Processor

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
	return nil
}

func (r Receiver) validate() error {
	if !namePattern.MatchString(r.Name) {
		return fmt.Errorf("Name %q: use lowercase letters, digits and dashes", r.Name)
	}
	if !auth.ValidTenant(r.Tenant) {
		return fmt.Errorf("receiver %q has no valid Tenant: name whose calls these are", r.Name)
	}
	for _, m := range r.Methods {
		switch strings.ToUpper(m) {
		case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return fmt.Errorf("receiver %q: %q is not a method a webhook arrives with", r.Name, m)
		}
	}
	if r.Validator == nil && len(r.Secret) == 0 {
		return fmt.Errorf("receiver %q has no Secret: a call nobody signed is not accepted", r.Name)
	}
	if r.Process == nil {
		return fmt.Errorf("receiver %q has no Process: name what handles its calls", r.Name)
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
	if c.Server.UserAgent == "" {
		c.Server.UserAgent = DefaultUserAgent
	}
	if c.Server.Timeout == 0 {
		c.Server.Timeout = DefaultTimeout
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
		if r.Respond == nil {
			r.Respond = RespondOK{}
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
