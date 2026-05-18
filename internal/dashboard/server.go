package dashboard

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/balyakin/aishield/internal/auditlog"
)

//go:embed assets/*
var assets embed.FS

type Options struct {
	LogFile            string
	Listen             string
	Password           string
	PasswordEnv        string
	Version            string
	EnabledPIIEntities int
}

type Server struct {
	options     Options
	startedAt   time.Time
	password    string
	connections int64
}

func New(options Options) (*Server, error) {
	if options.Listen == "" {
		options.Listen = "127.0.0.1:17891"
	}
	password := options.Password
	if password == "" && options.PasswordEnv != "" {
		password = os.Getenv(options.PasswordEnv)
	}
	if !isLoopbackListen(options.Listen) && password == "" {
		return nil, fmt.Errorf("non-loopback dashboard listen address requires Basic Auth password")
	}
	return &Server{options: options, startedAt: time.Now().UTC(), password: password}, nil
}

func (server *Server) ListenAndServe() error {
	httpServer := &http.Server{
		Addr:      server.options.Listen,
		Handler:   server.routes(),
		ConnState: server.connState,
	}
	return httpServer.ListenAndServe()
}

func (server *Server) Handler() http.Handler {
	return server.routes()
}

func (server *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.withAuth(server.index))
	mux.HandleFunc("/api/health", server.withAuth(server.health))
	mux.HandleFunc("/api/stats", server.withAuth(server.stats))
	mux.HandleFunc("/api/events", server.withAuth(server.events))
	mux.HandleFunc("/api/events/", server.withAuth(server.eventByID))
	mux.HandleFunc("/api/sessions/", server.withAuth(server.sessionByID))
	mux.HandleFunc("/api/export", server.withAuth(server.export))
	return mux
}

func (server *Server) index(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		if strings.HasPrefix(request.URL.Path, "/api/") {
			writeError(writer, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		http.NotFound(writer, request)
		return
	}
	data, err := assets.ReadFile("assets/index.html")
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "asset_error", "dashboard asset is unavailable")
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = writer.Write(data)
}

func (server *Server) health(writer http.ResponseWriter, request *http.Request) {
	info, _ := os.Stat(server.options.LogFile)
	var size int64
	var modified string
	if info != nil {
		size = info.Size()
		modified = info.ModTime().UTC().Format(time.RFC3339Nano)
	}
	writeJSON(writer, map[string]interface{}{
		"version":              server.options.Version,
		"uptime_seconds":       int(time.Since(server.startedAt).Seconds()),
		"log_file":             server.options.LogFile,
		"log_file_size":        size,
		"log_file_modified":    modified,
		"pii_entities_enabled": server.options.EnabledPIIEntities,
		"active_connections":   atomic.LoadInt64(&server.connections),
		"scanner_status":       scannerStatus(server.options.EnabledPIIEntities),
	})
}

func (server *Server) stats(writer http.ResponseWriter, request *http.Request) {
	since := 24 * time.Hour
	if value := request.URL.Query().Get("since"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_since", "since must be a duration such as 24h")
			return
		}
		since = parsed
	}
	stats, err := auditlog.CollectStats(server.options.LogFile, since)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "stats_failed", "failed to read audit log")
		return
	}
	writeJSON(writer, stats)
}

func (server *Server) events(writer http.ResponseWriter, request *http.Request) {
	filter, page, err := parseEventQuery(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_filter", err.Error())
		return
	}
	result, err := auditlog.List(server.options.LogFile, filter, page)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "events_failed", "failed to read audit log")
		return
	}
	writeJSON(writer, result)
}

func (server *Server) eventByID(writer http.ResponseWriter, request *http.Request) {
	eventID := strings.TrimPrefix(request.URL.Path, "/api/events/")
	if eventID == "" {
		writeError(writer, http.StatusBadRequest, "missing_event_id", "event_id is required")
		return
	}
	event, ok, err := auditlog.Get(server.options.LogFile, eventID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "event_failed", "failed to read audit log")
		return
	}
	if !ok {
		writeError(writer, http.StatusNotFound, "not_found", "event not found")
		return
	}
	writeJSON(writer, event)
}

func (server *Server) sessionByID(writer http.ResponseWriter, request *http.Request) {
	sessionID := strings.TrimPrefix(request.URL.Path, "/api/sessions/")
	if sessionID == "" {
		writeError(writer, http.StatusBadRequest, "missing_session_id", "session_id is required")
		return
	}
	events, err := auditlog.Session(server.options.LogFile, sessionID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "session_failed", "failed to read audit log")
		return
	}
	writeJSON(writer, map[string]interface{}{"session_id": sessionID, "events": events})
}

func (server *Server) export(writer http.ResponseWriter, request *http.Request) {
	from, err := auditlog.ParseTimeParam(request.URL.Query().Get("from"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_from", err.Error())
		return
	}
	to, err := auditlog.ParseTimeParam(request.URL.Query().Get("to"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_to", err.Error())
		return
	}
	format := request.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	filter := auditlog.Filter{From: from, To: to}
	switch format {
	case "csv":
		writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		if err := auditlog.ExportCSV(writer, server.options.LogFile, filter); err != nil {
			writeError(writer, http.StatusInternalServerError, "export_failed", "failed to export audit log")
		}
	case "jsonl":
		writer.Header().Set("Content-Type", "application/x-ndjson")
		if err := auditlog.ExportJSONL(writer, server.options.LogFile, filter); err != nil {
			writeError(writer, http.StatusInternalServerError, "export_failed", "failed to export audit log")
		}
	default:
		writeError(writer, http.StatusBadRequest, "invalid_format", "format must be csv or jsonl")
	}
}

func parseEventQuery(request *http.Request) (auditlog.Filter, auditlog.Page, error) {
	query := request.URL.Query()
	page := 1
	if value := query.Get("page"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 {
			return auditlog.Filter{}, auditlog.Page{}, fmt.Errorf("page must be a positive integer")
		}
		page = parsed
	}
	perPage := 50
	if value := query.Get("per_page"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 {
			return auditlog.Filter{}, auditlog.Page{}, fmt.Errorf("per_page must be a positive integer")
		}
		if parsed > 500 {
			parsed = 500
		}
		perPage = parsed
	}
	from, err := auditlog.ParseTimeParam(query.Get("from"))
	if err != nil {
		return auditlog.Filter{}, auditlog.Page{}, err
	}
	to, err := auditlog.ParseTimeParam(query.Get("to"))
	if err != nil {
		return auditlog.Filter{}, auditlog.Page{}, err
	}
	filter := auditlog.Filter{
		Type:      query.Get("type"),
		PIIType:   query.Get("pii_type"),
		Query:     query.Get("q"),
		SessionID: query.Get("session_id"),
		TraceID:   query.Get("trace_id"),
		From:      from,
		To:        to,
	}
	pageSpec := auditlog.Page{Page: page, PerPage: perPage, After: query.Get("after")}
	return filter, pageSpec, nil
}

func (server *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if server.password != "" {
			_, password, ok := request.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(password), []byte(server.password)) != 1 {
				writer.Header().Set("WWW-Authenticate", `Basic realm="aishield"`)
				writeError(writer, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}
		}
		next(writer, request)
	}
}

func (server *Server) connState(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		atomic.AddInt64(&server.connections, 1)
	case http.StateClosed, http.StateHijacked:
		atomic.AddInt64(&server.connections, -1)
	}
}

func writeJSON(writer http.ResponseWriter, value interface{}) {
	writer.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(writer)
	_ = encoder.Encode(value)
}

func writeError(writer http.ResponseWriter, status int, code string, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]interface{}{
		"error": map[string]string{"code": code, "message": message},
	})
}

func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost"
	}
	return ip.IsLoopback()
}

func scannerStatus(enabledEntities int) string {
	if enabledEntities <= 0 {
		return "disabled"
	}
	return "enabled"
}
