package pii

type StreamScanner struct {
	scanner   *Scanner
	pending   string
	holdBytes int
}

func NewStreamScanner(scanner *Scanner) *StreamScanner {
	holdBytes := 64
	if scanner != nil && scanner.options.StreamBufferBytes > 0 {
		holdBytes = scanner.options.StreamBufferBytes
	}
	return &StreamScanner{scanner: scanner, holdBytes: holdBytes}
}

func (stream *StreamScanner) ScanChunk(chunk string) ScanResult {
	if stream == nil || stream.scanner == nil || !stream.scanner.options.Enabled {
		return ScanResult{MaskedValue: chunk, Counts: map[string]int{}}
	}
	stream.pending += chunk
	if len(stream.pending) <= stream.holdBytes {
		return ScanResult{MaskedValue: "", Counts: map[string]int{}}
	}

	emitUntil := len(stream.pending) - stream.holdBytes
	emitUntil = validPrefixLength(stream.pending, emitUntil)
	findings := stream.scanner.Findings(stream.pending)
	for _, finding := range findings {
		if finding.Start < emitUntil && finding.End > emitUntil {
			emitUntil = finding.Start
			break
		}
	}
	emittedInput := stream.pending[:emitUntil]
	stream.pending = stream.pending[emitUntil:]

	emittedFindings := make([]Finding, 0)
	for _, finding := range findings {
		if finding.End <= emitUntil {
			emittedFindings = append(emittedFindings, finding)
		}
	}
	masked := ApplyFindings(emittedInput, emittedFindings)
	return ScanResult{
		MaskedValue: masked,
		Changed:     masked != emittedInput,
		Counts:      countFindings(emittedFindings),
		Findings:    emittedFindings,
	}
}

func (stream *StreamScanner) Flush() ScanResult {
	if stream == nil || stream.scanner == nil || stream.pending == "" {
		return ScanResult{MaskedValue: "", Counts: map[string]int{}}
	}
	pending := stream.pending
	stream.pending = ""
	return stream.scanner.Scan(pending)
}
