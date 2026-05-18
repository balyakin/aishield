package logger

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/balyakin/aishield/internal/dataprotection"
	"github.com/balyakin/aishield/internal/parser"
	"github.com/balyakin/aishield/internal/pii"
	"github.com/balyakin/aishield/internal/policy"
	"github.com/balyakin/aishield/internal/secrets"
)

const SchemaVersion = 2

type Logger struct {
	file      *os.File
	protector *dataprotection.Processor
	sessionID string
	agent     string
	cwd       string
	mutex     sync.Mutex
}

type Event struct {
	SchemaVersion  int                     `json:"schema_version"`
	Timestamp      string                  `json:"ts"`
	SessionID      string                  `json:"session_id"`
	EventID        string                  `json:"event_id"`
	TraceID        string                  `json:"trace_id,omitempty"`
	Backend        string                  `json:"backend"`
	Type           string                  `json:"type"`
	Agent          string                  `json:"agent,omitempty"`
	Cwd            string                  `json:"cwd,omitempty"`
	RawMasked      string                  `json:"raw_masked,omitempty"`
	Parsed         *parser.ParsedCommand   `json:"parsed,omitempty"`
	Decision       string                  `json:"decision,omitempty"`
	Rule           string                  `json:"rule,omitempty"`
	MatchedRules   []string                `json:"matched_rules,omitempty"`
	Severity       string                  `json:"severity,omitempty"`
	ExitCode       *int                    `json:"exit_code,omitempty"`
	UserAction     string                  `json:"user_action,omitempty"`
	Message        string                  `json:"msg,omitempty"`
	Config         map[string]interface{}  `json:"config,omitempty"`
	Summary        map[string]interface{}  `json:"summary,omitempty"`
	PIIFound       bool                    `json:"pii_found,omitempty"`
	PIICounts      map[string]int          `json:"pii_counts,omitempty"`
	PIIFindings    []pii.Finding           `json:"pii_findings,omitempty"`
	SecretCounts   map[string]int          `json:"secret_counts,omitempty"`
	DataProtection *dataprotection.Summary `json:"data_protection,omitempty"`
	PreSanitized   bool                    `json:"-"`
}

func New(path string, masker *secrets.Masker, agent string, cwd string) (*Logger, error) {
	return NewWithSession(path, masker, agent, cwd, "")
}

func NewWithSession(path string, masker *secrets.Masker, agent string, cwd string, sessionID string) (*Logger, error) {
	return NewProtectedWithSession(path, dataprotection.New(masker, nil), agent, cwd, sessionID)
}

func NewProtected(path string, protector *dataprotection.Processor, agent string, cwd string) (*Logger, error) {
	return NewProtectedWithSession(path, protector, agent, cwd, "")
}

func NewProtectedWithSession(path string, protector *dataprotection.Processor, agent string, cwd string, sessionID string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(cleanLogPath(path)), 0o755); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if sessionID == "" {
		sessionID = newEventID()
	}

	return &Logger{
		file:      file,
		protector: protector,
		sessionID: sessionID,
		agent:     agent,
		cwd:       cwd,
	}, nil
}

func (logger *Logger) SessionID() string {
	return logger.sessionID
}

func (logger *Logger) Close() error {
	if logger.file == nil {
		return nil
	}
	return logger.file.Close()
}

func (logger *Logger) Log(event Event) error {
	logger.mutex.Lock()
	defer logger.mutex.Unlock()

	event.SchemaVersion = SchemaVersion
	event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	event.SessionID = logger.sessionID
	event.EventID = newEventID()
	if event.Backend == "" {
		event.Backend = "cli"
	}
	if event.Agent == "" {
		event.Agent = logger.agent
	}
	if event.Cwd == "" {
		event.Cwd = logger.cwd
	}
	logger.sanitizeEvent(&event)

	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = logger.file.Write(append(encoded, '\n'))
	return err
}

func (logger *Logger) LogDecision(backend string, command parser.ParsedCommand, result policy.EvalResult) error {
	return logger.LogDecisionWithTrace(backend, command, result, "")
}

func (logger *Logger) LogDecisionWithTrace(backend string, command parser.ParsedCommand, result policy.EvalResult, traceID string) error {
	parsedCommand := command
	return logger.Log(Event{
		Backend:      backend,
		Type:         "decision",
		TraceID:      traceID,
		RawMasked:    command.Raw,
		Parsed:       &parsedCommand,
		Decision:     string(result.Decision),
		Rule:         result.Rule,
		MatchedRules: result.MatchedRules,
		Severity:     result.Severity,
		Message:      result.Reason,
	})
}

func NewTraceID() string {
	return "trc_" + strings.ToLower(newEventID())
}

func (logger *Logger) sanitizeEvent(event *Event) {
	if logger.protector == nil {
		return
	}
	aggregate := dataprotection.EmptyResult("")
	if !event.PreSanitized {
		event.RawMasked = logger.protectString(event.RawMasked, &aggregate)
	}
	event.Message = logger.protectString(event.Message, &aggregate)
	event.Agent = logger.protectString(event.Agent, &aggregate)
	event.Cwd = logger.protectString(event.Cwd, &aggregate)
	if event.Parsed != nil {
		logger.protectParsed(event.Parsed, &aggregate)
	}
	event.Config = logger.protectInterfaceMap(event.Config, &aggregate)
	event.Summary = logger.protectInterfaceMap(event.Summary, &aggregate)
	if len(event.PIICounts) > 0 {
		aggregate.PIICounts = mergeCounts(aggregate.PIICounts, event.PIICounts)
	}
	if len(event.SecretCounts) > 0 {
		aggregate.SecretCounts = mergeCounts(aggregate.SecretCounts, event.SecretCounts)
	}
	if len(event.PIIFindings) > 0 {
		aggregate.PIIFindings = append(aggregate.PIIFindings, event.PIIFindings...)
	}
	event.PIICounts = aggregate.PIICounts
	event.SecretCounts = aggregate.SecretCounts
	event.PIIFindings = aggregate.PIIFindings
	event.PIIFound = total(aggregate.PIICounts) > 0
	summary := aggregate.Summary
	summary.PIITotal = total(aggregate.PIICounts)
	summary.SecretTotal = total(aggregate.SecretCounts)
	summary.CompositePII = distinctPositive(aggregate.PIICounts) >= 2
	summary.Minimized = true
	summary.OriginalValuesLogged = false
	if summary.PIITotal > 0 || summary.SecretTotal > 0 || event.Type == "output" || event.Type == "decision" {
		event.DataProtection = &summary
	}
	if len(event.PIICounts) == 0 {
		event.PIICounts = nil
	}
	if len(event.SecretCounts) == 0 {
		event.SecretCounts = nil
	}
	if len(event.PIIFindings) == 0 {
		event.PIIFindings = nil
	}
}

func (logger *Logger) protectString(value string, aggregate *dataprotection.Result) string {
	if value == "" {
		return value
	}
	result := logger.protector.ProtectString(value)
	*aggregate = aggregate.Merge(result)
	return result.Value
}

func (logger *Logger) protectParsed(command *parser.ParsedCommand, aggregate *dataprotection.Result) {
	command.Raw = logger.protectString(command.Raw, aggregate)
	for index, arg := range command.Args {
		command.Args[index] = logger.protectString(arg, aggregate)
	}
	for key, value := range command.EnvVars {
		command.EnvVars[key] = logger.protectString(value, aggregate)
	}
	for index := range command.Pipes {
		logger.protectParsed(&command.Pipes[index], aggregate)
	}
	for index, path := range command.FilePaths {
		command.FilePaths[index] = logger.protectString(path, aggregate)
	}
}

func (logger *Logger) protectInterfaceMap(values map[string]interface{}, aggregate *dataprotection.Result) map[string]interface{} {
	if len(values) == 0 {
		return values
	}
	result := make(map[string]interface{}, len(values))
	for key, value := range values {
		result[key] = logger.protectValue(value, aggregate)
	}
	return result
}

func (logger *Logger) protectValue(value interface{}, aggregate *dataprotection.Result) interface{} {
	switch typed := value.(type) {
	case string:
		return logger.protectString(typed, aggregate)
	case []string:
		result := make([]string, len(typed))
		for index, item := range typed {
			result[index] = logger.protectString(item, aggregate)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(typed))
		for index, item := range typed {
			result[index] = logger.protectValue(item, aggregate)
		}
		return result
	case map[string]interface{}:
		return logger.protectInterfaceMap(typed, aggregate)
	case map[string]string:
		result := make(map[string]string, len(typed))
		for key, item := range typed {
			result[key] = logger.protectString(item, aggregate)
		}
		return result
	default:
		return value
	}
}

func mergeCounts(left map[string]int, right map[string]int) map[string]int {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	result := make(map[string]int)
	for key, value := range left {
		result[key] += value
	}
	for key, value := range right {
		result[key] += value
	}
	return result
}

func total(counts map[string]int) int {
	totalCount := 0
	for _, count := range counts {
		totalCount += count
	}
	return totalCount
}

func distinctPositive(counts map[string]int) int {
	totalCount := 0
	for _, count := range counts {
		if count > 0 {
			totalCount++
		}
	}
	return totalCount
}

func cleanLogPath(path string) string {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return filepath.Join(".", filepath.Base(path))
	}
	return path
}

func newEventID() string {
	return newULID(time.Now().UTC())
}

func newULID(timestamp time.Time) string {
	var buffer [16]byte
	milliseconds := uint64(timestamp.UnixNano() / int64(time.Millisecond))
	buffer[0] = byte(milliseconds >> 40)
	buffer[1] = byte(milliseconds >> 32)
	buffer[2] = byte(milliseconds >> 24)
	buffer[3] = byte(milliseconds >> 16)
	buffer[4] = byte(milliseconds >> 8)
	buffer[5] = byte(milliseconds)
	_, err := rand.Read(buffer[6:])
	if err != nil {
		binary.BigEndian.PutUint64(buffer[8:], uint64(timestamp.UnixNano()))
	}

	return encodeCrockfordBase32(buffer)
}

func encodeCrockfordBase32(buffer [16]byte) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	value := new(big.Int).SetBytes(buffer[:])
	mask := big.NewInt(31)
	encoded := make([]byte, 26)
	for index := len(encoded) - 1; index >= 0; index-- {
		digit := new(big.Int).And(value, mask).Int64()
		encoded[index] = alphabet[digit]
		value.Rsh(value, 5)
	}
	return string(encoded)
}
