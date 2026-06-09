package client

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.source.akamai.com/terraform-provider-eaa/pkg/testsupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopSigner struct{}

func (noopSigner) SignRequest(_ *http.Request) {}
func (noopSigner) CheckRequestLimit(_ int)     {}

func newTestClient(t *testing.T, handler http.Handler) *EaaClient {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	t.Cleanup(ts.Close)
	return &EaaClient{
		Signer:     noopSigner{},
		Client:     ts.Client(),
		Host:       ts.Listener.Addr().String(),
		ContractID: "test-contract",
	}
}

func jsonHandler(statusCode int, body interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		testsupport.WriteJSONResponse(w, statusCode, body)
	}
}

func jsonHandlerWithCapture(statusCode int, body interface{}) (http.HandlerFunc, *bytes.Buffer) {
	captured := &bytes.Buffer{}
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			io.Copy(captured, r.Body) //nolint:errcheck // test helper
		}
		testsupport.WriteJSONResponse(w, statusCode, body)
	}
	return handler, captured
}

func errorJSONHandler(statusCode int, detail string) http.HandlerFunc {
	return jsonHandler(statusCode, ErrorResponse{
		Type:   "error",
		Title:  http.StatusText(statusCode),
		Detail: detail,
	})
}

type pathRouter struct {
	t      *testing.T
	routes map[string]http.HandlerFunc
}

func newPathRouter(t *testing.T) *pathRouter {
	return &pathRouter{t: t, routes: make(map[string]http.HandlerFunc)}
}

func (pr *pathRouter) Handle(method, path string, handler http.HandlerFunc) {
	pr.routes[method+" "+path] = handler
}

func (pr *pathRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	if h, ok := pr.routes[key]; ok {
		h(w, r)
		return
	}
	pr.t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
}

func requireErrIs(t *testing.T, err error, wantErr bool, errIs error) bool {
	t.Helper()
	return testsupport.RequireErrIs(t, err, wantErr, errIs)
}

// toIntCase holds a single test case for string-to-int conversion tests.
type toIntCase[S ~string] struct {
	input    S
	expected int
	wantErr  bool
}

func testToInt[S ~string](t *testing.T, convFunc func(S) (int, error), tests map[string]toIntCase[S]) {
	t.Helper()
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := convFunc(tc.input)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// toStringCase holds a single test case for int-to-string conversion tests.
type toStringCase[I ~int] struct {
	input    I
	expected string
	wantErr  bool
}

func testToString[I ~int](t *testing.T, convFunc func(I) (string, error), tests map[string]toStringCase[I]) {
	t.Helper()
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := convFunc(tc.input)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
