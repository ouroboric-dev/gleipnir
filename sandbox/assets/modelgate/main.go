// Command ygg-modelgate is the model gate (local-models spec §3.5, §6): the only path from a sandbox to
// llama-server. It runs in the model server's container, in front of the router:
//
//	ygg-modelgate -listen :<port> -upstream http://127.0.0.1:8080 -allow /etc/ygg-models/allowed
//
// It passes a request to the upstream only when all of these hold:
//
//  1. The method is POST and the request target is exactly /v1/chat/completions: no query (the router reads
//     ?autoload= from it), no escaped or doubled slash, no dot segment. It asks for no upgrade (no Upgrade header,
//     and no Connection header naming upgrade), so the connection never turns into a tunnel past these checks, and
//     its body is not encoded (no Content-Encoding but identity), so the bytes checked are the bytes read.
//  2. The body is at most 32 MiB of UTF-8 JSON: one object, with one key "model" whose value is a string.
//  3. That string equals the trimmed content of the allow file, which it reads on each request, so a new run's
//     model needs no restart.
//  4. At most 8 requests are in flight: a request holds a slot from before its body is read until its response
//     ends, so the bodies held in memory are at most 8 times 32 MiB.
//  5. The body arrives within 60 seconds of the headers. The limit is on reading the body only; a response that
//     streams for longer is not cut.
//
// Otherwise it answers 403 (method, path, upgrade, encoding or model), 413 (size), 400 (not such JSON), 408 (the
// body was too slow) or 503 (no allow file, an empty one, or 8 requests already in flight), and the upstream never
// sees the request. It passes the body it checked, byte for byte, and streams
// the response as the upstream writes it.
//
// It is a standalone program with the standard library only, built in the image's builder stage; gleipnir embeds
// its source (sandbox/models.go) and its tests build it the same way.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	chatPath = "/v1/chat/completions"
	maxBody  = 32 << 20 // 32 MiB

	maxInFlight = 8                // requests passed at once; the next gets 503
	bodyWindow  = 60 * time.Second // from the headers to the last byte of the body
)

// bodyWindowOverride is empty in every build of the image. A test sets it at link time (-X main.bodyWindowOverride=300ms)
// to wait less than 60 seconds; no flag or environment variable can.
var bodyWindowOverride string

func main() {
	listen := flag.String("listen", "", "the address to listen on, such as :8090")
	upstream := flag.String("upstream", "", "llama-server's URL, such as http://127.0.0.1:8080")
	allow := flag.String("allow", "", "the file that holds the allowed model's name")
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("ygg-modelgate: ")
	up, err := checkFlags(*listen, *upstream, *allow, flag.NArg())
	if err != nil {
		fmt.Fprintln(os.Stderr, "ygg-modelgate: "+err.Error())
		flag.Usage()
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s, in front of %s", ln.Addr(), up)
	srv := &http.Server{
		Handler:           newGate(up, *allow),
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.Default(),
	}
	log.Fatal(srv.Serve(ln))
}

// checkFlags checks the three flags and returns the upstream's URL: plain HTTP to a host and port, with no path,
// query or user.
func checkFlags(listen, upstream, allow string, extra int) (*url.URL, error) {
	if listen == "" || upstream == "" || allow == "" || extra != 0 {
		return nil, errors.New("-listen, -upstream and -allow are required, and nothing else")
	}
	up, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("-upstream: %w", err)
	}
	if up.Scheme != "http" || up.Host == "" || up.User != nil || (up.Path != "" && up.Path != "/") || up.RawQuery != "" || up.ForceQuery || up.Fragment != "" {
		return nil, fmt.Errorf("-upstream %q must be http://HOST:PORT, with no path", upstream)
	}
	return &url.URL{Scheme: "http", Host: up.Host}, nil
}

// gate is the handler: it checks a request and passes it to proxy.
type gate struct {
	allow  string
	proxy  *httputil.ReverseProxy
	slots  chan struct{} // a token per request in flight
	window time.Duration // how long a body may take
}

func newGate(up *url.URL, allow string) *gate {
	window := bodyWindow
	if d, err := time.ParseDuration(bodyWindowOverride); err == nil && d > 0 {
		window = d
	}
	return &gate{allow: allow, slots: make(chan struct{}, maxInFlight), window: window, proxy: &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(up)
			r.Out.URL.Path, r.Out.URL.RawPath, r.Out.URL.RawQuery, r.Out.URL.ForceQuery = chatPath, "", "", false
		},
		FlushInterval: -1, // flush after each write: a chat's stream reaches the client as llama-server writes it
		ErrorLog:      log.Default(),
	}}
}

func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The request target as the client sent it, so no decoding or cleaning can turn another path into this one.
	if r.Method != http.MethodPost || r.RequestURI != chatPath {
		g.refuse(w, r, http.StatusForbidden, "only POST "+chatPath+" passes")
		return
	}
	if why := plainRequest(r.Header); why != "" {
		g.refuse(w, r, http.StatusForbidden, why)
		return
	}
	allowed, err := os.ReadFile(g.allow)
	model := strings.TrimSpace(string(allowed))
	if err != nil || model == "" {
		g.refuse(w, r, http.StatusServiceUnavailable, "no model is allowed")
		return
	}
	if r.ContentLength > maxBody {
		g.refuse(w, r, http.StatusRequestEntityTooLarge, "the body is above 32 MiB")
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		g.refuse(w, r, http.StatusServiceUnavailable, "8 requests are in flight; try again")
		return
	}
	// The deadline bounds the read of the body and is cleared after it, so it never cuts the response.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(g.window))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	_ = rc.SetReadDeadline(time.Time{})
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// Close after the answer: the server would otherwise wait for the rest of the body to reuse the connection.
			w.Header().Set("Connection", "close")
			g.refuse(w, r, http.StatusRequestTimeout, "the body did not arrive within 60 seconds")
			return
		}
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			g.refuse(w, r, http.StatusRequestEntityTooLarge, "the body is above 32 MiB")
			return
		}
		g.refuse(w, r, http.StatusBadRequest, "the body could not be read")
		return
	}
	asked, err := modelOf(body)
	if err != nil {
		g.refuse(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if asked != model {
		g.refuse(w, r, http.StatusForbidden, "only the allowed model passes")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	g.proxy.ServeHTTP(w, r)
}

// plainRequest says why a request's headers are refused, or "" when they ask for no upgrade and the body is not
// encoded. The reverse proxy passes an upgrade through and then copies bytes both ways, unchecked; llama-server may
// decode a body the gate read as other bytes.
func plainRequest(h http.Header) string {
	if _, ok := h["Upgrade"]; ok {
		return "an upgrade does not pass"
	}
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return "an upgrade does not pass"
			}
		}
	}
	for _, v := range h.Values("Content-Encoding") {
		for _, token := range strings.Split(v, ",") {
			if t := strings.TrimSpace(token); t != "" && !strings.EqualFold(t, "identity") {
				return "an encoded body does not pass"
			}
		}
	}
	return ""
}

// modelOf returns the string "model" of a body that must be one JSON object, in UTF-8, with "model" once. A key is
// matched exactly, as llama-server matches it; a second "model" is refused, so no parser can read another one.
func modelOf(body []byte) (string, error) {
	if !utf8.Valid(body) {
		return "", errors.New("the body is not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", errors.New("the body is not a JSON object")
	}
	var model *string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return "", errors.New("the body is not JSON")
		}
		key, _ := t.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return "", errors.New("the body is not JSON")
		}
		if key != "model" {
			continue
		}
		if model != nil {
			return "", errors.New("the body names model twice")
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return "", errors.New("model is not a string")
		}
		model = &s
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return "", errors.New("the body is not JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", errors.New("the body holds more than one JSON value")
	}
	if model == nil {
		return "", errors.New("the body names no model")
	}
	return *model, nil
}

// refuse answers status with a JSON error in the shape llama-server uses, and logs the refusal without the body.
func (g *gate) refuse(w http.ResponseWriter, r *http.Request, status int, why string) {
	log.Printf("refused %s %q: %d, %s", r.Method, r.RequestURI, status, why)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{"error": map[string]any{"code": status, "message": "ygg-modelgate: " + why, "type": "ygg_modelgate"}})
	_, _ = w.Write(append(b, '\n'))
}
