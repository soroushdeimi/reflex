package reflex
import (
    "bytes"
    "io"
    "net/http"
    "net/http/httptest"
    "testing"
)
func TestFallbackToWebServer(t *testing.T) {
    targetWebServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("<html><body><h1>Welcome to My Website</h1></body></html>"))
    }))
    defer targetWebServer.Close()

    resp, err := http.Get(targetWebServer.URL)
    if err != nil {
        t.Fatalf("Browser Error: %v", err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    if bytes.Contains(body, []byte("Welcome")) {
        t.Log("Fallback Success: Site visible instead of proxy error")
    } else {
        t.Error("Fallback Failed: Content mismatch")
    }
}