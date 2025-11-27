package testutils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// LoadFixtureBytes returns the entire contents of the given file as a byte slice
func LoadFixtureBytes(t *testing.T, path string) []byte {
	t.Helper()
	
	var fullPath string
	
	// Try multiple path resolutions
	// 1. Try as-is (absolute or relative to current working directory)
	if _, err := os.Stat(path); err == nil {
		fullPath = path
	} else {
		// 2. Try relative to pkg/eaaprovider (from project root)
		fullPath = filepath.Join("pkg/eaaprovider", path)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			// 3. Try relative to testutils package (for tests in testutils)
			fullPath = filepath.Join("..", "eaaprovider", path)
			if _, err := os.Stat(fullPath); os.IsNotExist(err) {
				// All path resolutions failed, will use original path for error message
				fullPath = path
			}
		}
	}
	
	contents, err := os.ReadFile(fullPath)
	require.NoError(t, err, "Failed to load fixture: %s (tried: %s)", path, fullPath)
	return contents
}

// LoadFixtureStringf returns the entire contents of the given file as a string
// Supports format string with arguments
func LoadFixtureStringf(t *testing.T, format string, args ...interface{}) string {
	return string(LoadFixtureBytes(t, fmt.Sprintf(format, args...)))
}

// LoadFixtureString returns the entire contents of the given file as a string
func LoadFixtureString(t *testing.T, path string) string {
	return string(LoadFixtureBytes(t, path))
}

