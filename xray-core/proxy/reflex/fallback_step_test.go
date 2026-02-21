package reflex

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFallbackStep(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("SAYT_MAJAZI_OK"))
	}))
	defer fake.Close()
	resp, _ := http.Get(fake.URL)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) == "SAYT_MAJAZI_OK" {
		t.Log("Fallback Server Response: OK")
	}
}
