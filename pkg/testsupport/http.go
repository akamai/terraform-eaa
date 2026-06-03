package testsupport

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// WriteJSONResponse writes a JSON response body for HTTP handler tests.
func WriteJSONResponse(w http.ResponseWriter, statusCode int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if body != nil {
		if err := json.NewEncoder(w).Encode(body); err != nil {
			panic(err)
		}
	}
}

// BuildJSONHTTPResponse builds an http.Response with a JSON body for RoundTripper tests.
func BuildJSONHTTPResponse(req *http.Request, statusCode int, body interface{}, header http.Header) (*http.Response, error) {
	var bodyBytes []byte
	if body != nil {
		marshaled, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyBytes = marshaled
	}

	if header == nil {
		header = make(http.Header)
	}

	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
		Header:     header,
		Request:    req,
	}, nil
}
