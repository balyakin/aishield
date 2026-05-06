package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/balyakin/aishield/internal/exitcode"
	"github.com/balyakin/aishield/internal/fsguard"
	"github.com/balyakin/aishield/internal/logger"
	"github.com/balyakin/aishield/internal/notifier"
	"github.com/balyakin/aishield/internal/parser"
	"github.com/balyakin/aishield/internal/policy"
	"github.com/balyakin/aishield/internal/secrets"
)

type PTYProxy struct {
	command    []string
	env        []string
	workDir    string
	policy     *policy.Engine
	masker     *secrets.Masker
	fsguard    *fsguard.Guard
	logger     *logger.Logger
	notifier   *notifier.Notifier
	confirmTTL time.Duration
	warnAction policy.Decision
	dryRun     bool
	logOutput  bool
	stats      Stats
	statsMutex sync.Mutex
}

type Stats struct {
	Commands      int
	Allowed       int
	Warned        int
	Blocked       int
	SecretsMasked int
}

type Options struct {
	Command    []string
	Env        []string
	WorkDir    string
	Policy     *policy.Engine
	Masker     *secrets.Masker
	FSGuard    *fsguard.Guard
	Logger     *logger.Logger
	Notifier   *notifier.Notifier
	ConfirmTTL time.Duration
	WarnAction policy.Decision
	DryRun     bool
	LogOutput  bool
}

func New(options Options) *PTYProxy {
	return &PTYProxy{
		command:    options.Command,
		env:        options.Env,
		workDir:    options.WorkDir,
		policy:     options.Policy,
		masker:     options.Masker,
		fsguard:    options.FSGuard,
		logger:     options.Logger,
		notifier:   options.Notifier,
		confirmTTL: options.ConfirmTTL,
		warnAction: options.WarnAction,
		dryRun:     options.DryRun,
		logOutput:  options.LogOutput,
	}
}

func (proxy *PTYProxy) Run() (Stats, int, error) {
	if len(proxy.command) == 0 {
		return proxy.stats, exitcode.RuntimeError, fmt.Errorf("command is required")
	}

	command := exec.Command(proxy.command[0], proxy.command[1:]...)
	command.Env = proxy.env
	command.Dir = proxy.workDir

	ptmx, err := pty.Start(command)
	if err != nil {
		return proxy.stats, exitcode.RuntimeError, err
	}
	defer func() {
		_ = ptmx.Close()
	}()

	_ = pty.InheritSize(os.Stdin, ptmx)
	processDone := make(chan struct{})
	proxy.forwardSignals(command, ptmx, processDone)
	if command.Process != nil {
		_ = proxy.logger.Log(logger.Event{
			Backend: "pty",
			Type:    "lifecycle",
			Message: "child process started",
			Summary: map[string]interface{}{
				"pid":          command.Process.Pid,
				"process_tree": SnapshotProcessTree(command.Process.Pid),
			},
		})
	}

	outputDone := make(chan struct{})
	go func() {
		proxy.copyOutput(ptmx)
		close(outputDone)
	}()

	inputDone := make(chan struct{})
	go func() {
		proxy.copyInput(ptmx)
		close(inputDone)
	}()

	waitErr := command.Wait()
	close(processDone)
	_ = ptmx.Close()
	<-outputDone

	select {
	case <-inputDone:
	case <-time.After(100 * time.Millisecond):
	}

	if waitErr == nil {
		return proxy.stats, exitcode.Success, nil
	}

	if exitError, ok := waitErr.(*exec.ExitError); ok {
		return proxy.stats, exitError.ExitCode(), nil
	}
	return proxy.stats, exitcode.ChildProcessFailed, waitErr
}

func (proxy *PTYProxy) copyInput(ptmx *os.File) {
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := readInputLine(reader)
		if line != "" {
			if proxy.handleInputLine(ptmx, line, reader) != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (proxy *PTYProxy) handleInputLine(writer io.Writer, line string, reader *bufio.Reader) error {
	command := parser.Parse(line)
	if !command.IsShell {
		return writeToChild(writer, line)
	}

	proxy.incrementCommands()
	pathResult := proxy.fsguard.Check(command.FilePaths, fsguard.IsWriteCommand(command))
	if !pathResult.Allowed {
		result := policy.EvalResult{
			Decision: policy.Block,
			Rule:     "filesystem-guard",
			Severity: policy.SeverityCritical,
			Reason:   pathResult.Reason,
		}
		proxy.incrementBlocked()
		_ = proxy.logger.LogDecision("pty", command, result)
		_ = proxy.notifyDecision(notifier.EventBlocked, command, result)
		fmt.Fprintf(os.Stderr, "\n[aishield] BLOCKED: %s", line)
		return nil
	}

	result := proxy.policy.Evaluate(command)
	if proxy.dryRun {
		result.Decision = policy.Allow
	}
	_ = proxy.logger.LogDecision("pty", command, result)

	switch result.Decision {
	case policy.Allow:
		proxy.incrementAllowed()
		return writeToChild(writer, line)
	case policy.Warn:
		_ = proxy.notifyDecision(notifier.EventWarned, command, result)
		if proxy.allowWarn(command, result, reader) {
			proxy.incrementWarned()
			return writeToChild(writer, line)
		}
		proxy.incrementBlocked()
		_ = proxy.notifyDecision(notifier.EventBlocked, command, result)
		return nil
	case policy.Block:
		proxy.incrementBlocked()
		_ = proxy.notifyDecision(notifier.EventBlocked, command, result)
		fmt.Fprintf(os.Stderr, "\n[aishield] BLOCKED: %sRule: %s\nReason: %s\n", line, result.Rule, result.Reason)
		return nil
	default:
		return nil
	}
}

func (proxy *PTYProxy) allowWarn(command parser.ParsedCommand, result policy.EvalResult, reader *bufio.Reader) bool {
	if !isInteractiveTerminal() {
		return proxy.warnAction == policy.Allow
	}
	return proxy.confirm(command, result, reader)
}

func (proxy *PTYProxy) confirm(command parser.ParsedCommand, result policy.EvalResult, reader *bufio.Reader) bool {
	if reader == nil {
		return false
	}
	fmt.Fprintf(os.Stderr, "\n[aishield] WARNING: %s", command.Raw)
	fmt.Fprintf(os.Stderr, "Rule: %s\nReason: %s\nAllow? [y/N]: ", result.Rule, result.Reason)

	answer := make(chan string, 1)
	go func() {
		value, _ := readInputLine(reader)
		answer <- value
	}()

	select {
	case value := <-answer:
		value = strings.TrimSpace(strings.ToLower(value))
		return value == "y" || value == "yes"
	case <-time.After(proxy.confirmTTL):
		return false
	}
}

func readInputLine(reader *bufio.Reader) (string, error) {
	var builder strings.Builder
	for {
		value, err := reader.ReadByte()
		if err != nil {
			return builder.String(), err
		}
		builder.WriteByte(value)
		if value == '\n' || value == '\r' {
			return builder.String(), nil
		}
	}
}

func writeToChild(writer io.Writer, line string) error {
	if writer == nil {
		return nil
	}
	_, err := writer.Write([]byte(line))
	return err
}

func (proxy *PTYProxy) copyOutput(ptmx *os.File) {
	buffer := make([]byte, 4096)
	for {
		count, err := ptmx.Read(buffer)
		if count > 0 {
			output := buffer[:count]
			maskResult := proxy.masker.MaskString(string(output))
			proxy.countSecretMasks(maskResult)
			_, _ = os.Stdout.Write([]byte(maskResult.Value))
			if proxy.logOutput {
				_ = proxy.logger.Log(logger.Event{
					Backend:   "pty",
					Type:      "output",
					RawMasked: maskResult.Value,
				})
			}
		}
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
	}
}

func (proxy *PTYProxy) forwardSignals(command *exec.Cmd, ptmx *os.File, processDone <-chan struct{}) {
	signalChannel := make(chan os.Signal, 4)
	signal.Notify(signalChannel, syscall.SIGWINCH, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for receivedSignal := range signalChannel {
			switch receivedSignal {
			case syscall.SIGWINCH:
				_ = pty.InheritSize(os.Stdin, ptmx)
			case syscall.SIGINT, syscall.SIGTERM:
				if command.Process != nil {
					_ = command.Process.Signal(receivedSignal)
					go killAfterTimeout(command, processDone)
				}
			}
		}
	}()
}

func killAfterTimeout(command *exec.Cmd, processDone <-chan struct{}) {
	select {
	case <-processDone:
	case <-time.After(5 * time.Second):
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	}
}

func (proxy *PTYProxy) countSecretMasks(maskResult secrets.MaskResult) {
	if !maskResult.Changed {
		return
	}
	totalCount := 0
	for _, count := range maskResult.Counts {
		totalCount = totalCount + count
	}
	proxy.statsMutex.Lock()
	proxy.stats.SecretsMasked = proxy.stats.SecretsMasked + totalCount
	proxy.statsMutex.Unlock()

	for name, count := range maskResult.Counts {
		_ = proxy.logger.Log(logger.Event{
			Backend: "pty",
			Type:    "secret_masked",
			Message: fmt.Sprintf("masked %d occurrence(s) of %s in output", count, name),
		})
		_ = proxy.notifySecretMasked(name, count)
	}
}

func (proxy *PTYProxy) notifyDecision(eventType string, command parser.ParsedCommand, result policy.EvalResult) error {
	if proxy.notifier == nil {
		return nil
	}
	return proxy.notifier.Notify(context.Background(), notifier.Event{
		SessionID:        proxy.logger.SessionID(),
		EventType:        eventType,
		Command:          command.Raw,
		Rule:             result.Rule,
		Reason:           result.Reason,
		Agent:            proxy.command[0],
		Severity:         result.Severity,
		WorkingDirectory: proxy.workDir,
	})
}

func (proxy *PTYProxy) notifySecretMasked(name string, count int) error {
	if proxy.notifier == nil {
		return nil
	}
	return proxy.notifier.Notify(context.Background(), notifier.Event{
		SessionID:        proxy.logger.SessionID(),
		EventType:        notifier.EventSecretMasked,
		Reason:           fmt.Sprintf("masked %d occurrence(s) of %s in output", count, name),
		Agent:            proxy.command[0],
		Severity:         policy.SeverityWarn,
		WorkingDirectory: proxy.workDir,
	})
}

func isInteractiveTerminal() bool {
	if os.Getenv("CI") == "true" {
		return false
	}

	stdinInfo, stdinErr := os.Stdin.Stat()
	stderrInfo, stderrErr := os.Stderr.Stat()
	if stdinErr != nil || stderrErr != nil {
		return false
	}
	if stdinInfo.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return stderrInfo.Mode()&os.ModeCharDevice != 0
}

func (proxy *PTYProxy) incrementCommands() {
	proxy.statsMutex.Lock()
	defer proxy.statsMutex.Unlock()
	proxy.stats.Commands++
}

func (proxy *PTYProxy) incrementAllowed() {
	proxy.statsMutex.Lock()
	defer proxy.statsMutex.Unlock()
	proxy.stats.Allowed++
}

func (proxy *PTYProxy) incrementWarned() {
	proxy.statsMutex.Lock()
	defer proxy.statsMutex.Unlock()
	proxy.stats.Warned++
}

func (proxy *PTYProxy) incrementBlocked() {
	proxy.statsMutex.Lock()
	defer proxy.statsMutex.Unlock()
	proxy.stats.Blocked++
}
