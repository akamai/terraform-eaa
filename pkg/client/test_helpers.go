package client

import (
	"net/http"
)

// MockSigner implements edgegrid.Signer for testing
// This centralizes the mock signer to avoid duplicate declarations
type MockSigner struct{}

func (m *MockSigner) SignRequest(req *http.Request) {
	// No-op: don't actually sign in tests
}

func (m *MockSigner) CheckRequestLimit(requestLimit int) {
	// No-op: don't check limits in tests
}
