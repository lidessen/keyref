package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIErrorCodeParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "revision_conflict"})
	}))
	defer srv.Close()
	c := New(srv.URL, nil)
	_, err := c.PairStatus("nonce")
	if err == nil || Code(err) != "revision_conflict" {
		t.Fatalf("got %v, want revision_conflict", err)
	}
}

func TestBearerTokenAttached(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Query().Get("cursor") != "7" {
			t.Errorf("cursor %q", r.URL.Query().Get("cursor"))
		}
		json.NewEncoder(w).Encode(map[string]any{"cursor": 8, "changes": []any{}})
	}))
	defer srv.Close()
	c := New(srv.URL, func() (string, error) { return "tok123", nil })
	if _, err := c.Sync(7); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok123" {
		t.Fatalf("auth %q", gotAuth)
	}
}

func TestPairStatusComplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pair/status" {
			t.Errorf("path %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status": "complete", "vault_id": "v", "device_id": "d",
		})
	}))
	defer srv.Close()
	c := New(srv.URL, nil)
	st, err := c.PairStatus("n")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "complete" || st.VaultID != "v" || st.DeviceID != "d" {
		t.Fatalf("%+v", st)
	}
}

func TestSessionTwoStep(t *testing.T) {
	step := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		step++
		if step == 1 {
			if _, ok := body["signature"]; ok {
				t.Error("step 1 must not carry a signature")
			}
			json.NewEncoder(w).Encode(map[string]any{"challenge": "QUJD", "expires_at": 1})
			return
		}
		if body["signature"] == nil || body["challenge"] == nil {
			t.Error("step 2 missing fields")
		}
		json.NewEncoder(w).Encode(map[string]any{"token": "t0", "expires_at": 2, "origin": "x", "plan": "unlimited"})
	}))
	defer srv.Close()
	c := New(srv.URL, nil)
	ch, _, err := c.SessionChallenge("dev")
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := c.SessionToken("dev", ch, []byte("sig"))
	if err != nil || tok != "t0" {
		t.Fatalf("token %q err %v", tok, err)
	}
}
