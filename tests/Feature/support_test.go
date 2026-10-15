package feature_test

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arandu-io/framework/data"
	fhttp "github.com/arandu-io/framework/http"
	"github.com/arandu-io/framework/security"
	hedatabase "github.com/arandu-io/hesape/database"
	sqliteconnector "github.com/arandu-io/hesape/database/connectors/sqlite"
	"github.com/arandu-io/hesape/database/migrations"
	"github.com/arandu-io/hesape/events"
	"github.com/arandu-io/hesape/queue"

	webhook "github.com/hyz-is/arandu-webhook"
)

const (
	tenant = "acme"
	dsn    = "?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(20000)"
	// sharedSecret is what a sender and this application's receiver share.
	sharedSecret = "shared-secret-shared-secret-0123"
)

// world is an application with the module over a real database, the jobs
// table, a worker, and a router with a session store.
type world struct {
	db       *data.DB
	module   *webhook.Module
	sessions *security.SessionStore
	router   *fhttp.Router
	worker   *queue.Worker
	jobs     *queue.DatabaseQueue
	handled  *handled
	schema   migrations.Connection
}

// handled is what the test processors saw.
type handled struct {
	mu    sync.Mutex
	calls []*webhook.Call
	fail  error
}

func (h *handled) Process(_ context.Context, g security.Grant, call *webhook.Call) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if data.Tenant(g) != call.TenantID {
		panic("the processing Grant is not the call's tenant")
	}
	h.calls = append(h.calls, call)
	return h.fail
}

func (h *handled) seen() []*webhook.Call {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*webhook.Call(nil), h.calls...)
}

// install builds the world. configure adjusts the configuration after the
// test processor is set on every receiver that has none.
func install(t *testing.T, configure func(*webhook.Config, *handled)) *world {
	t.Helper()
	path := filepath.Join(t.TempDir(), "webhook.sqlite")
	handle, err := sql.Open(sqliteconnector.SQLiteConnector{}.DriverName(), "file:"+path+dsn)
	if err != nil {
		t.Fatal(err)
	}
	handle.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = handle.Close() })
	connection := hedatabase.NewConnection(handle, path, "", map[string]any{"driver": string(hedatabase.DialectSQLite), "name": "webhook-test"})
	db := data.Wrap(handle, data.DialectSQLite)
	sessions := security.NewSessionStore([]byte(appKey), time.Hour, false, security.NewMemoryBackend())

	h := &handled{}
	cfg := webhook.Config{Key: []byte(appKey)}
	if configure != nil {
		configure(&cfg, h)
	}
	for i := range cfg.Receivers {
		if cfg.Receivers[i].Process == nil {
			cfg.Receivers[i].Process = h
		}
	}
	module, err := webhook.New(cfg, db, sessions)
	if err != nil {
		t.Fatal(err)
	}
	jobs := queue.NewDatabaseQueue(db)
	schema := hedatabase.ForMigrations(connection)
	for _, m := range append(append(jobs.Migrations(), events.NewModule().Migrations()...), module.Migrations()...) {
		if err := m.Up(context.Background(), schema); err != nil {
			t.Fatalf("applying %s: %v", m.GetName(), err)
		}
	}
	worker := queue.NewWorker(jobs, queue.WorkerOptions{Queue: webhook.DefaultQueue, Sleep: time.Millisecond})
	if err := module.RegisterJobHandlers(worker); err != nil {
		t.Fatal(err)
	}
	router := fhttp.NewRouter()
	module.Routes(router.ForModule(module.Name()))
	return &world{db: db, module: module, sessions: sessions, router: router, worker: worker, jobs: jobs, handled: h, schema: schema}
}

// work runs the next job on the webhooks queue and answers the handler's
// error.
func (w *world) work(t *testing.T) error {
	t.Helper()
	return w.worker.RunNextJob(context.Background())
}

// pending is how many jobs wait on the webhooks queue.
func (w *world) pending(t *testing.T) int {
	t.Helper()
	n, err := w.jobs.Size(context.Background(), webhook.DefaultQueue)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// send makes one request to the router.
func (w *world) send(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	return rec
}

// signIn answers the cookies of a session for the subject.
func (w *world) signIn(t *testing.T, subject security.Subject) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if _, err := w.sessions.Start(context.Background(), rec, subject); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()
}

// as makes a JSON request with the cookies.
func (w *world) as(t *testing.T, cookies []*http.Cookie, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Accept", "application/json")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return w.send(t, req)
}

// calls are the stored calls of the tenant, oldest first.
func (w *world) calls(t *testing.T, tenantID string) []*webhook.Call {
	t.Helper()
	rows, err := webhook.Calls(w.db).OrderBy("created_at").OrderBy("id").Get(context.Background(), security.SystemGrant(webhook.CallReceive, tenantID))
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// manager is a subject of the tenant given every action of the package.
func manager(tenantID string) security.Subject {
	return security.Subject{ID: "manager-" + tenantID, Tenant: tenantID, Actions: webhook.Actions(), Verified: true}
}

// httptestBody is a request body.
func httptestBody(body string) io.ReadCloser { return io.NopCloser(strings.NewReader(body)) }
