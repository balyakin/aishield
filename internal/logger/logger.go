package logger

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/balyakin/aishield/internal/parser"
	"github.com/balyakin/aishield/internal/policy"
	"github.com/balyakin/aishield/internal/secrets"
)

const SchemaVersion = 1

type Logger struct {
	file      *os.File
	masker    *secrets.Masker
	sessionID string
	agent     string
	cwd       string
	mutex     sync.Mutex
}

type Event struct {
	SchemaVersion int                    `json:"schema_version"`
	Timestamp     string                 `json:"ts"`
	SessionID     string                 `json:"session_id"`
	EventID       string                 `json:"event_id"`
	Backend       string                 `json:"backend"`
	Type          string                 `json:"type"`
	Agent         string                 `json:"agent,omitempty"`
	Cwd           string                 `json:"cwd,omitempty"`
	RawMasked     string                 `json:"raw_masked,omitempty"`
	Parsed        *parser.ParsedCommand  `json:"parsed,omitempty"`
	Decision      string                 `json:"decision,omitempty"`
	Rule          string                 `json:"rule,omitempty"`
	MatchedRules  []string               `json:"matched_rules,omitempty"`
	Severity      string                 `json:"severity,omitempty"`
	ExitCode      *int                   `json:"exit_code,omitempty"`
	UserAction    string                 `json:"user_action,omitempty"`
	Message       string                 `json:"msg,omitempty"`
	Config        map[string]interface{} `json:"config,omitempty"`
	Summary       map[string]interface{} `json:"summary,omitempty"`
}

func New(path string, masker *secrets.Masker, agent string, cwd string) (*Logger, error) {
	return NewWithSession(path, masker, agent, cwd, "")
}

func NewWithSession(path string, masker *secrets.Masker, agent string, cwd string, sessionID string) (*Logger, error) {
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
		masker:    masker,
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
	if event.RawMasked != "" && logger.masker != nil {
		event.RawMasked = logger.masker.MaskString(event.RawMasked).Value
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = logger.file.Write(append(encoded, '\n'))
	return err
}

func (logger *Logger) LogDecision(backend string, command parser.ParsedCommand, result policy.EvalResult) error {
	parsedCommand := command
	return logger.Log(Event{
		Backend:      backend,
		Type:         "decision",
		RawMasked:    command.Raw,
		Parsed:       &parsedCommand,
		Decision:     string(result.Decision),
		Rule:         result.Rule,
		MatchedRules: result.MatchedRules,
		Severity:     result.Severity,
		Message:      result.Reason,
	})
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
