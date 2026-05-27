package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

type noopSigner struct{}

func (noopSigner) SignRequest(_ *http.Request) {}
func (noopSigner) CheckRequestLimit(_ int)     {}

//nolint:unused,gocritic // test helper for future tests
func newTestClient(t *testing.T, handler http.Handler) (*EaaClient, func()) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	ec := &EaaClient{
		Signer:     noopSigner{},
		Logger:     hclog.NewNullLogger(),
		Client:     ts.Client(),
		Host:       ts.Listener.Addr().String(),
		ContractID: "test-contract",
	}
	return ec, ts.Close
}

//nolint:unused // test helper for future tests
func mustEncodeJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err, "failed to encode JSON")
	return data
}

//nolint:unused // test helper for future tests
func mustDecodeJSONBody(t *testing.T, r *http.Request, v interface{}) {
	t.Helper()
	data, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, v))
}

//nolint:unused // test helper for future tests
func jsonHandler(statusCode int, body interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			json.NewEncoder(w).Encode(body) //nolint:errcheck // test helper, error handling not needed
		}
	}
}

//nolint:unused // test helper for future tests
func errorJSONHandler(statusCode int, detail string) http.HandlerFunc {
	return jsonHandler(statusCode, ErrorResponse{
		Type:   "error",
		Title:  http.StatusText(statusCode),
		Detail: detail,
	})
}

//nolint:unused // test helper for future tests
type pathRouter struct {
	routes map[string]http.HandlerFunc
}

//nolint:unused // test helper for future tests
func newPathRouter() *pathRouter {
	return &pathRouter{routes: make(map[string]http.HandlerFunc)}
}

//nolint:unused // test helper for future tests
func (pr *pathRouter) Handle(method, path string, handler http.HandlerFunc) {
	pr.routes[method+" "+path] = handler
}

//nolint:unused // test helper for future tests
func (pr *pathRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	if h, ok := pr.routes[key]; ok {
		h(w, r)
		return
	}
	http.NotFound(w, r)
}
