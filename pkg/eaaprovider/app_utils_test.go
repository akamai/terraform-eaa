package eaaprovider

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCleanupOrphanedApp(t *testing.T) {
	appID := "test-orphan-app-uuid"

	t.Run("app_not_found_returns_true", func(t *testing.T) {
		mockClient, mockTransport := createMockClient(t)

		getPattern := fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)
		mockTransport.Responses[getPattern] = MockResponse{
			StatusCode: 404,
			Body:       map[string]interface{}{"detail": "not found"},
		}

		result := cleanupOrphanedApp(context.Background(), mockClient, appID)
		assert.True(t, result, "should return true when app not found")
	})

	t.Run("app_check_failure_returns_false", func(t *testing.T) {
		mockClient, mockTransport := createMockClient(t)

		getPattern := fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID)
		mockTransport.Responses[getPattern] = MockResponse{
			StatusCode: 500,
			Body:       map[string]interface{}{"detail": "internal error"},
		}

		result := cleanupOrphanedApp(context.Background(), mockClient, appID)
		assert.False(t, result, "should return false when app existence check fails")
	})

	t.Run("app_found_delete_succeeds_verify_confirms", func(t *testing.T) {
		mockClient, _ := createMockClient(t)
		getCallCount := 0
		statefulTransport := &statefulMockTransport{
			t: t,
			handler: func(method, path string) MockResponse {
				key := fmt.Sprintf("%s %s", method, path)
				switch {
				case key == fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID):
					getCallCount++
					if getCallCount == 1 {
						return MockResponse{
							StatusCode: 200,
							Body: map[string]interface{}{
								"uuid_url": appID,
								"name":     "orphan-app",
							},
						}
					}
					return MockResponse{
						StatusCode: 404,
						Body:       map[string]interface{}{"detail": "not found"},
					}
				case key == fmt.Sprintf("DELETE /crux/v1/mgmt-pop/apps/%s", appID):
					return MockResponse{
						StatusCode: 200,
						Body:       map[string]interface{}{"status": "deleted"},
					}
				default:
					t.Errorf("unexpected request: %s", key)
					return MockResponse{StatusCode: 404}
				}
			},
		}
		mockClient.Client.Transport = statefulTransport

		result := cleanupOrphanedApp(context.Background(), mockClient, appID)
		assert.True(t, result, "should return true when app deleted and verified")
	})

	t.Run("app_found_delete_fails_returns_false", func(t *testing.T) {
		mockClient, _ := createMockClient(t)

		statefulTransport := &statefulMockTransport{
			t: t,
			handler: func(method, path string) MockResponse {
				key := fmt.Sprintf("%s %s", method, path)
				switch {
				case key == fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID):
					return MockResponse{
						StatusCode: 200,
						Body: map[string]interface{}{
							"uuid_url": appID,
							"name":     "orphan-app",
						},
					}
				case key == fmt.Sprintf("DELETE /crux/v1/mgmt-pop/apps/%s", appID):
					return MockResponse{
						StatusCode: 500,
						Body:       map[string]interface{}{"detail": "internal error"},
					}
				default:
					t.Errorf("unexpected request: %s", key)
					return MockResponse{StatusCode: 404}
				}
			},
		}
		mockClient.Client.Transport = statefulTransport

		result := cleanupOrphanedApp(context.Background(), mockClient, appID)
		assert.False(t, result, "should return false when delete fails")
	})

	t.Run("app_found_delete_succeeds_but_still_exists_returns_false", func(t *testing.T) {
		mockClient, _ := createMockClient(t)

		statefulTransport := &statefulMockTransport{
			t: t,
			handler: func(method, path string) MockResponse {
				key := fmt.Sprintf("%s %s", method, path)
				switch {
				case key == fmt.Sprintf("GET /crux/v1/mgmt-pop/apps/%s", appID):
					// Always returns 200 (app still exists after delete)
					return MockResponse{
						StatusCode: 200,
						Body: map[string]interface{}{
							"uuid_url": appID,
							"name":     "orphan-app",
						},
					}
				case key == fmt.Sprintf("DELETE /crux/v1/mgmt-pop/apps/%s", appID):
					return MockResponse{
						StatusCode: 200,
						Body:       map[string]interface{}{"status": "deleted"},
					}
				default:
					t.Errorf("unexpected request: %s", key)
					return MockResponse{StatusCode: 404}
				}
			},
		}
		mockClient.Client.Transport = statefulTransport

		result := cleanupOrphanedApp(context.Background(), mockClient, appID)
		assert.False(t, result, "should return false when app still exists after deletion")
	})
}
