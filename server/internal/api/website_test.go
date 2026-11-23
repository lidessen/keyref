package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicHomepageWithAccountVault(t *testing.T) {
	accountVault := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := New(nil, nil, nil, Config{AccountVault: accountVault}).Handler()
	request := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	home := request("/")
	if home.Code != http.StatusOK || !strings.Contains(home.Body.String(), `href="/manage/"`) {
		t.Fatalf("homepage with account vault returned status %d or omitted the vault link", home.Code)
	}
	if manage := request("/manage/"); manage.Code != http.StatusNoContent {
		t.Fatalf("account vault route returned %d", manage.Code)
	}
	installer := request("/install.sh")
	const target = "https://raw.githubusercontent.com/lidessen/keyref/main/scripts/install.sh"
	if installer.Code != http.StatusFound || installer.Header().Get("Location") != target {
		t.Fatalf("installer returned %d with location %q", installer.Code, installer.Header().Get("Location"))
	}
}
