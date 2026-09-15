package metrics

import (
	"net/http"
)

// ContentTypeLatest is the official MIME specification for Prometheus text exposition (version 0.0.4).
const ContentTypeLatest = "text/plain; version=0.0.4; charset=utf-8"

// Handler returns an http.Handler that serializes and serves Prometheus metrics from reg.
//
// Conforming to standard Prometheus scraping conventions, it accepts GET and HEAD requests.
// Any unsupported HTTP methods receive a 405 Method Not Allowed response with an Allow header.
func Handler(reg *Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", ContentTypeLatest)
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = reg.WritePrometheus(w)
	})
}

// Handler returns an http.Handler serving Prometheus metrics from this Registry.
func (r *Registry) Handler() http.Handler {
	return Handler(r)
}
