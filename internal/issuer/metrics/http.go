package metrics

import (
	"net/http"
	"slices"
	"time"
)

// OtherRoute is the route of the requests to a path not served by the
// process: the paths are not recorded, so that probes for random paths
// cannot create series (D-10).
const OtherRoute = "other"

// methods are the HTTP methods recorded as such; the others are recorded
// as "_OTHER", per the OpenTelemetry HTTP conventions.
var methods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
	http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace,
}

// Middleware records the duration of every request to next, by route (one
// of routes, the exact paths the process serves, or OtherRoute), method and
// status.
func (m *Metrics) Middleware(routes []string, next http.Handler) http.Handler {
	if m == nil || m.httpDuration == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		route := OtherRoute
		if slices.Contains(routes, r.URL.Path) {
			route = r.URL.Path
		}
		method := "_OTHER"
		if slices.Contains(methods, r.Method) {
			method = r.Method
		}
		m.recordHTTP(r.Context(), route, method, sw.status, time.Since(start))
	})
}

// statusWriter captures the status code of a response.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status, w.wroteHeader = status, true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
