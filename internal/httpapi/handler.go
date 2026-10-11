// Package httpapi exposes the OpenAPI contract over net/http.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mskmemory/gocpe-ai/internal/service"
)

type Handler struct {
	svc     *service.Service
	auth    Authenticator
	timeout time.Duration
}

func New(svc *service.Service, auth Authenticator) (http.Handler, error) {
	if svc == nil || auth == nil {
		return nil, fmt.Errorf("service and authenticator are required")
	}
	return &Handler{svc, auth, 15 * time.Second}, nil
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := service.NewID()
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		if recover() != nil {
			h.fail(w, id, fmt.Errorf("handler panic"))
		}
	}()
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	r = r.WithContext(ctx)
	auth := strings.Fields(r.Header.Get("Authorization"))
	if len(r.Header.Values("Authorization")) != 1 || len(auth) != 2 || !strings.EqualFold(auth[0], "Bearer") {
		h.fail(w, id, &service.Fault{Status: 401, Code: "UNAUTHENTICATED", Message: "Bearer token required"})
		return
	}
	p, err := h.auth.Authenticate(ctx, auth[1])
	if err != nil || p.OwnerID == "" {
		h.fail(w, id, &service.Fault{Status: 401, Code: "UNAUTHENTICATED", Message: "Invalid bearer token"})
		return
	}
	method, path := r.Method, r.URL.Path
	if (method == http.MethodGet && !p.Read) || (method == http.MethodPost && !p.Write) {
		h.fail(w, id, &service.Fault{Status: 403, Code: "FORBIDDEN", Message: "Operation is not permitted"})
		return
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	// Do not silently normalize malformed routes, trailing slashes, or repeated slashes.
	if path != "/"+strings.Join(segments, "/") {
		h.fail(w, id, service.ErrNotFound)
		return
	}
	var kind, jobID string
	expected := http.MethodGet
	switch {
	case path == "/v1/providers":
		kind = "providers"
	case path == "/v1/package-searches":
		kind = "package_search"
		expected = http.MethodPost
	case path == "/v1/resolutions":
		kind = "resolution"
		expected = http.MethodPost
	case path == "/v1/cpes":
		kind = "cpes"
	case path == "/v1/purls":
		kind = "purls"
	case len(segments) >= 3 && segments[0] == "v1" && segments[1] == "resolutions":
		jobID = segments[2]
		if len(segments) == 3 {
			kind = "job"
		} else if len(segments) == 4 && segments[3] == "results" {
			kind = "results"
		} else if len(segments) == 4 && segments[3] == "cancel" {
			kind = "cancel"
			expected = http.MethodPost
		}
	}
	if kind == "" {
		h.fail(w, id, service.ErrNotFound)
		return
	}
	if method != expected {
		w.Header().Set("Allow", expected)
		h.fail(w, id, &service.Fault{Status: 405, Code: "METHOD_NOT_ALLOWED", Message: "Method is not allowed"})
		return
	}
	q, err := query(r, kind)
	if err != nil {
		h.fail(w, id, err)
		return
	}
	switch kind {
	case "providers":
		h.send(w, id, 200, "ProviderList", h.svc.Providers())
	case "package_search", "resolution":
		raw, e := body(w, r)
		if e != nil {
			h.fail(w, id, e)
			return
		}
		keys := r.Header.Values("Idempotency-Key")
		if len(keys) > 1 || (len(keys) == 1 && keys[0] == "") {
			h.fail(w, id, service.Invalid("", "Expected one nonempty Idempotency-Key header"))
			return
		}
		j, e := h.svc.Create(ctx, p.OwnerID, kind, r.Header.Get("Idempotency-Key"), raw)
		if e != nil {
			h.fail(w, id, e)
			return
		}
		w.Header().Set("Location", "/v1/resolutions/"+j.ID)
		w.Header().Set("Retry-After", "2")
		h.send(w, id, 202, "Job", j)
	case "job":
		j, e := h.svc.Get(ctx, p.OwnerID, jobID)
		if e != nil {
			h.fail(w, id, e)
			return
		}
		h.send(w, id, 200, "Job", j)
	case "cancel":
		if r.ContentLength != 0 {
			h.fail(w, id, service.Invalid("", "Cancel takes no request body"))
			return
		}
		j, accepted, e := h.svc.Cancel(ctx, p.OwnerID, jobID)
		if e != nil {
			h.fail(w, id, e)
			return
		}
		status := 200
		if accepted {
			status = 202
		}
		h.send(w, id, status, "Job", j)
	case "results":
		v, e := h.svc.Results(ctx, p.OwnerID, jobID, q["cursor"], atoi(q["limit"]))
		if e != nil {
			h.fail(w, id, e)
			return
		}
		h.send(w, id, 200, "ResultPage", v)
	case "cpes":
		v, e := h.svc.CPEs(ctx, p.OwnerID, q["cursor"], service.CPEQuery{PageQuery: service.PageQuery{Limit: atoi(q["limit"])}, Q: q["q"], Vendor: q["vendor"], Product: q["product"], Deprecated: q["deprecated"] == "true"})
		if e != nil {
			h.fail(w, id, e)
			return
		}
		h.send(w, id, 200, "CPEPage", v)
	case "purls":
		v, e := h.svc.PURLs(ctx, p.OwnerID, q["cursor"], service.PURLQuery{PageQuery: service.PageQuery{Limit: atoi(q["limit"])}, Q: q["q"], Type: q["type"], Namespace: q["namespace"], Name: q["name"]})
		if e != nil {
			h.fail(w, id, e)
			return
		}
		h.send(w, id, 200, "PURLPage", v)
	}
}
func atoi(s string) int { n, _ := strconv.Atoi(s); return n }
func query(r *http.Request, kind string) (map[string]string, error) {
	allowed := map[string]bool{}
	if kind == "results" || kind == "cpes" || kind == "purls" {
		allowed["limit"] = true
		allowed["cursor"] = true
	}
	if kind == "cpes" {
		for _, k := range []string{"q", "vendor", "product", "deprecated"} {
			allowed[k] = true
		}
	}
	if kind == "purls" {
		for _, k := range []string{"q", "type", "namespace", "name"} {
			allowed[k] = true
		}
	}
	bad := &service.Fault{Status: 400, Code: "INVALID_QUERY", Message: "Unknown, repeated, or invalid query parameter"}
	values, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		return nil, bad
	}
	out := map[string]string{}
	for k, vs := range values {
		if !allowed[k] || len(vs) != 1 || !utf8.ValidString(vs[0]) {
			return nil, bad
		}
		v := vs[0]
		if k == "cursor" {
			if len(v) > 4096 {
				return nil, bad
			}
		} else if len([]rune(v)) > 512 {
			return nil, bad
		}
		switch k {
		case "limit":
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 200 {
				return nil, bad
			}
		case "q":
			if strings.TrimSpace(v) == "" || len([]rune(v)) > 256 {
				return nil, bad
			}
		case "deprecated":
			if v != "true" && v != "false" {
				return nil, bad
			}
		}
		out[k] = v
	}
	return out, nil
}
func body(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	badType := &service.Fault{Status: 415, Code: "UNSUPPORTED_MEDIA_TYPE", Message: "Expected application/json encoded as UTF-8"}
	t, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || t != "application/json" {
		return nil, badType
	}
	if charset := params["charset"]; charset != "" && !strings.EqualFold(charset, "utf-8") {
		return nil, badType
	}
	if enc := r.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return nil, badType
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, service.MaxBodyBytes))
	if e != nil {
		var big *http.MaxBytesError
		if errors.As(e, &big) {
			return nil, &service.Fault{Status: 413, Code: "PAYLOAD_TOO_LARGE", Message: "Body exceeds 10 MiB"}
		}
		return nil, &service.Fault{Status: 400, Code: "INVALID_JSON", Message: "Could not read body"}
	}
	return b, nil
}
func (h *Handler) send(w http.ResponseWriter, id string, status int, schema string, v any) {
	if err := h.svc.ValidateOutput(schema, v); err != nil {
		h.fail(w, id, fmt.Errorf("invalid backend response"))
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		h.fail(w, id, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
func (h *Handler) fail(w http.ResponseWriter, id string, err error) {
	f := service.AsFault(err)
	if f.Status == 401 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="gocpe-ai"`)
	}
	if f.Status == 429 || f.Status == 503 {
		w.Header().Set("Retry-After", "2")
	}
	w.Header().Del("Location")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.Status)
	_ = json.NewEncoder(w).Encode(service.ErrorResponse{Error: service.Error{Code: f.Code, Message: f.Message, RequestID: id, Details: f.Details}})
}
