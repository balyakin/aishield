package auditlog

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/balyakin/aishield/internal/logger"
	"github.com/balyakin/aishield/internal/pii"
)

type Filter struct {
	Type             string
	PIIType          string
	SessionID        string
	TraceID          string
	Query            string
	MinPIIConfidence string
	From             time.Time
	To               time.Time
}

type Page struct {
	Page    int
	PerPage int
	After   string
}

type ListResult struct {
	Items     []logger.Event `json:"items"`
	Page      int            `json:"page"`
	PerPage   int            `json:"per_page"`
	NextAfter string         `json:"next_after"`
	HasMore   bool           `json:"has_more"`
	Skipped   int            `json:"skipped,omitempty"`
}

type Stats struct {
	Sessions        int            `json:"sessions"`
	Commands        int            `json:"commands"`
	Allowed         int            `json:"allowed"`
	Warned          int            `json:"warned"`
	Blocked         int            `json:"blocked"`
	SecretsMasked   int            `json:"secrets_masked"`
	PIIMasked       int            `json:"pii_masked"`
	PIITotal        int            `json:"pii_total"`
	PIITypes        map[string]int `json:"pii_types"`
	SecretTypes     map[string]int `json:"secret_types"`
	TopRules        map[string]int `json:"top_rules"`
	DecisionRatio   map[string]int `json:"decision_ratio"`
	BlockedCommands map[string]int `json:"blocked_commands"`
	Agents          map[string]int `json:"agents"`
	MalformedLines  int            `json:"malformed_lines"`
}

type RetentionReport struct {
	LogFile       string `json:"log_file"`
	Cutoff        string `json:"cutoff"`
	Removed       int    `json:"removed"`
	Retained      int    `json:"retained"`
	MalformedKept int    `json:"malformed_kept"`
	ArchivePath   string `json:"archive_path,omitempty"`
	Applied       bool   `json:"applied"`
}

func List(path string, filter Filter, page Page) (ListResult, error) {
	if page.PerPage <= 0 {
		page.PerPage = 50
	}
	if page.PerPage > 500 {
		page.PerPage = 500
	}
	if page.Page <= 0 {
		page.Page = 1
	}

	result := ListResult{Page: page.Page, PerPage: page.PerPage}
	startIndex := (page.Page - 1) * page.PerPage
	seenAfter := page.After == ""
	matched := 0
	err := ForEach(path, func(event logger.Event, raw string, offset int64) error {
		if !seenAfter {
			if event.EventID == page.After {
				seenAfter = true
			}
			return nil
		}
		if !Matches(event, filter) {
			return nil
		}
		if page.After == "" && matched < startIndex {
			matched++
			return nil
		}
		if len(result.Items) >= page.PerPage {
			result.HasMore = true
			return io.EOF
		}
		result.Items = append(result.Items, event)
		result.NextAfter = event.EventID
		matched++
		return nil
	}, func() {
		result.Skipped++
	})
	if err != nil && err != io.EOF {
		return result, err
	}
	return result, nil
}

func Get(path string, eventID string) (logger.Event, bool, error) {
	var found logger.Event
	ok := false
	err := ForEach(path, func(event logger.Event, raw string, offset int64) error {
		if event.EventID == eventID {
			found = event
			ok = true
			return io.EOF
		}
		return nil
	}, nil)
	if err != nil && err != io.EOF {
		return logger.Event{}, false, err
	}
	return found, ok, nil
}

func Session(path string, sessionID string) ([]logger.Event, error) {
	events := make([]logger.Event, 0)
	err := ForEach(path, func(event logger.Event, raw string, offset int64) error {
		if event.SessionID == sessionID {
			events = append(events, event)
		}
		return nil
	}, nil)
	return events, err
}

func CollectStats(path string, since time.Duration) (Stats, error) {
	filter := Filter{}
	if since > 0 {
		filter.From = time.Now().UTC().Add(-since)
	}
	stats := Stats{
		PIITypes:        make(map[string]int),
		SecretTypes:     make(map[string]int),
		TopRules:        make(map[string]int),
		DecisionRatio:   make(map[string]int),
		BlockedCommands: make(map[string]int),
		Agents:          make(map[string]int),
	}
	err := ForEach(path, func(event logger.Event, raw string, offset int64) error {
		if !Matches(event, filter) {
			return nil
		}
		switch event.Type {
		case "lifecycle":
			if event.Message == "session started" {
				stats.Sessions++
			}
		case "decision":
			stats.Commands++
			if event.Agent != "" {
				stats.Agents[event.Agent]++
			}
			stats.DecisionRatio[event.Decision]++
			switch event.Decision {
			case "allow":
				stats.Allowed++
			case "warn":
				stats.Warned++
			case "block":
				stats.Blocked++
				stats.BlockedCommands[event.RawMasked]++
			}
			if event.Rule != "" {
				stats.TopRules[event.Rule]++
			}
		case "secret_masked":
			if len(event.SecretCounts) == 0 {
				stats.SecretsMasked++
			}
		case "pii_masked":
			stats.PIIMasked++
		}
		for key, count := range event.PIICounts {
			stats.PIITypes[key] += count
			stats.PIITotal += count
		}
		for key, count := range event.SecretCounts {
			stats.SecretTypes[key] += count
			stats.SecretsMasked += count
		}
		return nil
	}, func() {
		stats.MalformedLines++
	})
	return stats, err
}

func ExportCSV(writer io.Writer, path string, filter Filter) error {
	csvWriter := csv.NewWriter(writer)
	header := []string{"ts", "event_id", "trace_id", "session_id", "type", "decision", "severity", "rule", "matched_rules", "pii_total", "pii_counts", "secret_total", "secret_counts", "raw_masked", "msg"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}
	err := ForEach(path, func(event logger.Event, raw string, offset int64) error {
		if !Matches(event, filter) {
			return nil
		}
		piiCounts, _ := json.Marshal(event.PIICounts)
		secretCounts, _ := json.Marshal(event.SecretCounts)
		matchedRules, _ := json.Marshal(event.MatchedRules)
		row := []string{
			event.Timestamp,
			event.EventID,
			event.TraceID,
			event.SessionID,
			event.Type,
			event.Decision,
			event.Severity,
			event.Rule,
			string(matchedRules),
			fmt.Sprintf("%d", mapTotal(event.PIICounts)),
			string(piiCounts),
			fmt.Sprintf("%d", mapTotal(event.SecretCounts)),
			string(secretCounts),
			event.RawMasked,
			event.Message,
		}
		return csvWriter.Write(row)
	}, nil)
	if err != nil {
		return err
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

func ExportJSONL(writer io.Writer, path string, filter Filter) error {
	encoder := json.NewEncoder(writer)
	return ForEach(path, func(event logger.Event, raw string, offset int64) error {
		if !Matches(event, filter) {
			return nil
		}
		return encoder.Encode(event)
	}, nil)
}

func RetentionPreview(path string, days int) (RetentionReport, error) {
	return retention(path, days, false, false)
}

func RetentionApply(path string, days int, archive bool) (RetentionReport, error) {
	return retention(path, days, archive, true)
}

func retention(path string, days int, archive bool, apply bool) (RetentionReport, error) {
	if days <= 0 {
		return RetentionReport{}, fmt.Errorf("days must be positive")
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	report := RetentionReport{LogFile: path, Cutoff: cutoff.Format(time.RFC3339), Applied: apply}
	if !apply {
		err := ForEachRaw(path, func(event logger.Event, raw []byte, valid bool) error {
			if !valid || !eventBefore(event, cutoff) {
				report.Retained++
				if !valid {
					report.MalformedKept++
				}
				return nil
			}
			report.Removed++
			return nil
		})
		return report, err
	}

	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return report, err
	}
	tempPath := tempFile.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()
	var archiveFile *os.File
	if archive {
		report.ArchivePath = fmt.Sprintf("%s.archive.%s.jsonl", path, time.Now().UTC().Format("20060102150405"))
		archiveFile, err = os.OpenFile(report.ArchivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = tempFile.Close()
			return report, err
		}
		defer func() {
			_ = archiveFile.Close()
		}()
	}

	err = ForEachRaw(path, func(event logger.Event, raw []byte, valid bool) error {
		if !valid || !eventBefore(event, cutoff) {
			report.Retained++
			if !valid {
				report.MalformedKept++
			}
			_, writeErr := tempFile.Write(ensureNewline(raw))
			return writeErr
		}
		report.Removed++
		if archiveFile != nil {
			_, writeErr := archiveFile.Write(ensureNewline(raw))
			return writeErr
		}
		return nil
	})
	if closeErr := tempFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return report, err
	}
	return report, os.Rename(tempPath, path)
}

func ensureNewline(raw []byte) []byte {
	if len(raw) == 0 || raw[len(raw)-1] == '\n' {
		return raw
	}
	return append(append([]byte{}, raw...), '\n')
}

func Matches(event logger.Event, filter Filter) bool {
	if filter.Type != "" && event.Type != filter.Type {
		return false
	}
	if filter.SessionID != "" && event.SessionID != filter.SessionID {
		return false
	}
	if filter.TraceID != "" && event.TraceID != filter.TraceID {
		return false
	}
	if !filter.From.IsZero() || !filter.To.IsZero() {
		timestamp, ok := parseTime(event.Timestamp)
		if !ok {
			return false
		}
		if !filter.From.IsZero() && timestamp.Before(filter.From) {
			return false
		}
		if !filter.To.IsZero() && timestamp.After(filter.To) {
			return false
		}
	}
	if filter.PIIType != "" && event.PIICounts[filter.PIIType] == 0 {
		return false
	}
	if filter.MinPIIConfidence != "" && !hasMinConfidence(event.PIIFindings, filter.MinPIIConfidence) {
		return false
	}
	if filter.Query != "" && !matchesQuery(event, filter.Query) {
		return false
	}
	return true
}

func ForEach(path string, fn func(event logger.Event, raw string, offset int64) error, onMalformed func()) error {
	return ForEachRaw(path, func(event logger.Event, raw []byte, valid bool) error {
		if !valid {
			if onMalformed != nil {
				onMalformed()
			}
			return nil
		}
		return fn(event, string(raw), 0)
	})
}

func ForEachRaw(path string, fn func(event logger.Event, raw []byte, valid bool) error) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			var event logger.Event
			valid := json.Unmarshal(line, &event) == nil
			if valid && event.SchemaVersion == 0 {
				event.SchemaVersion = 1
			}
			if callErr := fn(event, line, valid); callErr != nil {
				return callErr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func ParseTimeParam(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	if parsed, err := time.Parse("2006-01-02", value); err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid time %q", value)
}

func SortedCounts(counts map[string]int, limit int) []string {
	type item struct {
		key   string
		count int
	}
	items := make([]item, 0, len(counts))
	for key, count := range counts {
		items = append(items, item{key: key, count: count})
	}
	sort.Slice(items, func(left int, right int) bool {
		return items[left].count > items[right].count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, fmt.Sprintf("%s (%d)", item.key, item.count))
	}
	return result
}

func parseTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func eventBefore(event logger.Event, cutoff time.Time) bool {
	timestamp, ok := parseTime(event.Timestamp)
	return ok && timestamp.Before(cutoff)
}

func hasMinConfidence(findings []pii.Finding, minConfidence string) bool {
	minRank := pii.ConfidenceRank(minConfidence)
	for _, finding := range findings {
		if pii.ConfidenceRank(finding.Confidence) >= minRank {
			return true
		}
	}
	return false
}

func matchesQuery(event logger.Event, query string) bool {
	query = strings.ToLower(query)
	values := []string{
		event.RawMasked,
		event.Message,
		event.Decision,
		event.Rule,
		event.SessionID,
		event.TraceID,
		strings.Join(event.MatchedRules, " "),
	}
	for _, finding := range event.PIIFindings {
		values = append(values, finding.Type, finding.Confidence, finding.Source, finding.Encoding, finding.ContextHintMatched, finding.StructuredPath)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func mapTotal(values map[string]int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}
