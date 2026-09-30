package wires_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

// fakeOSV serves the two OSV endpoints TraceState uses. flask 2.0.0 has two
// advisories; everything else is clean.
func fakeOSV(t *testing.T) (*httptest.Server, *int32) {
	var detailCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string } `json:"package"`
				Version string                           `json:"version"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad querybatch body: %v", err)
		}
		type vuln struct {
			ID string `json:"id"`
		}
		results := make([]map[string][]vuln, len(req.Queries))
		for i, q := range req.Queries {
			results[i] = map[string][]vuln{}
			switch {
			case q.Package.Name == "flask" && q.Package.Ecosystem == "PyPI" && q.Version == "2.0.0":
				results[i]["vulns"] = []vuln{{"GHSA-m2qf-hxjv-5gpq"}, {"PYSEC-2023-62"}}
			case q.Package.Ecosystem == "Go" && strings.HasPrefix(q.Version, "v"):
				t.Errorf("Go versions must be sent without the v prefix, got %q", q.Version)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&detailCalls, 1)
		id := r.PathValue("id")
		sev := map[string]string{"GHSA-m2qf-hxjv-5gpq": "HIGH", "PYSEC-2023-62": ""}[id]
		fixed := map[string]string{"GHSA-m2qf-hxjv-5gpq": "2.3.2", "PYSEC-2023-62": "2.2.5"}[id]
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      id,
			"summary": "Possible disclosure of permanent session cookie",
			"affected": []any{
				map[string]any{
					"package": map[string]string{"name": "flask", "ecosystem": "PyPI"},
					"ranges":  []any{map[string]any{"events": []map[string]string{{"introduced": "0"}, {"fixed": fixed}}}},
				},
				map[string]any{ // another package in the same advisory must be ignored
					"package": map[string]string{"name": "werkzeug", "ecosystem": "PyPI"},
					"ranges":  []any{map[string]any{"events": []map[string]string{{"fixed": "9.9.9"}}}},
				},
			},
			"database_specific": map[string]string{"severity": sev},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &detailCalls
}

func TestKnownVulnerableDependencies(t *testing.T) {
	srv, detailCalls := fakeOSV(t)
	t.Setenv("TRACESTATE_OSV_URL", srv.URL)
	files := map[string]string{
		"requirements.txt":         "flask==2.0.0\nrequests==2.32.3\n",
		"svc/requirements-dev.txt": "flask==2.0.0\n",
		"go.mod":                   "module x\n\nrequire github.com/spf13/cobra v1.10.2\n",
	}

	// Offline, the online rule is not evaluated and nothing is sent anywhere.
	if got := scan(t, files, scanner.Options{}); find(got, "TS-DEP-001") != nil {
		t.Fatal("TS-DEP-001 ran without --online")
	}
	if *detailCalls != 0 {
		t.Fatal("OSV was contacted without --online")
	}

	got := scan(t, files, scanner.Options{Online: true})
	expect(t, got, "TS-DEP-001 requirements.txt:1", "TS-DEP-001 svc/requirements-dev.txt:1")
	f := find(got, "TS-DEP-001")
	if f.Severity != policy.High {
		t.Errorf("severity = %v, want high (the worst rated advisory)", f.Severity)
	}
	for _, want := range []string{"GHSA-m2qf-hxjv-5gpq", "PYSEC-2023-62", "fixed in 2.3.2"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("message %q lacks %q", f.Message, want)
		}
	}
	if strings.Contains(f.Message, "9.9.9") {
		t.Error("fixed version of another package in the advisory leaked into the message")
	}
	// flask==2.0.0 appears twice but each advisory is fetched once.
	if *detailCalls != 2 {
		t.Errorf("advisory detail requests = %d, want 2", *detailCalls)
	}
}

func TestOSVFailureIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	t.Setenv("TRACESTATE_OSV_URL", srv.URL)
	rs, _ := policy.DefaultRules()
	tg, _ := scanner.NewTarget(writeTree(t, map[string]string{"requirements.txt": "flask==2.0.0\n"}))
	if _, err := scanner.Run(t.Context(), tg, rs, scanner.Options{Online: true}); err == nil ||
		!strings.Contains(err.Error(), "429") {
		t.Fatalf("expected the OSV error to surface, got %v", err)
	}
}
