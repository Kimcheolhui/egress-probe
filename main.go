package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default values
const (
	defaultPort    = 443
	defaultTimeout = 5 * time.Second
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// Target represents a single FQDN:port to test.
type Target struct {
	Host string
	Port int
}

// PhaseResult holds the result of a single test phase.
type PhaseResult struct {
	Success  bool
	Duration time.Duration
	Detail   string
}

// TestResult holds all phase results for a single target.
type TestResult struct {
	Target Target
	DNS    PhaseResult
	TCP    PhaseResult
	TLS    PhaseResult
}

func main() {
	targets, timeout := parseConfig()

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no targets specified.\n")
		fmt.Fprintf(os.Stderr, "Set the TARGETS environment variable with comma-separated FQDN[:port] values.\n")
		fmt.Fprintf(os.Stderr, "Example: TARGETS=\"mcr.microsoft.com:443,registry.k8s.io\" %s\n", os.Args[0])
		os.Exit(1)
	}

	printHeader(targets, timeout)

	results := runTests(targets, timeout)

	printResults(results)

	// Exit with non-zero code if any test failed
	for _, r := range results {
		if !r.DNS.Success || !r.TCP.Success || !r.TLS.Success {
			os.Exit(1)
		}
	}
}

// parseConfig reads configuration from environment variables.
func parseConfig() ([]Target, time.Duration) {
	timeout := defaultTimeout
	if t := os.Getenv("TIMEOUT"); t != "" {
		if sec, err := strconv.Atoi(t); err == nil && sec > 0 {
			timeout = time.Duration(sec) * time.Second
		}
	}

	raw := os.Getenv("TARGETS")
	if raw == "" {
		return nil, timeout
	}

	var targets []Target
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		t := parseTarget(entry)
		targets = append(targets, t)
	}

	return targets, timeout
}

// parseTarget parses a "host:port", "host", or URL-style "scheme://host[:port]" string into a Target.
func parseTarget(s string) Target {
	// Strip scheme prefix and infer default port from it
	inferredPort := defaultPort
	if idx := strings.Index(s, "://"); idx != -1 {
		scheme := strings.ToLower(s[:idx])
		s = s[idx+3:]
		switch scheme {
		case "http":
			inferredPort = 80
		case "https":
			inferredPort = 443
		case "tcp", "tls":
			// keep defaultPort (443)
		}
	}

	// Strip trailing path (e.g. "google.com/path" → "google.com")
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}

	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// No port specified, use inferred port
		return Target{Host: s, Port: inferredPort}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		port = inferredPort
	}
	return Target{Host: host, Port: port}
}

// runTests executes all three phases for each target concurrently.
func runTests(targets []Target, timeout time.Duration) []TestResult {
	results := make([]TestResult, len(targets))
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target Target) {
			defer wg.Done()
			results[idx] = testTarget(target, timeout)
		}(i, t)
	}

	wg.Wait()
	return results
}

// testTarget runs the 3-phase validation pipeline for a single target.
func testTarget(target Target, timeout time.Duration) TestResult {
	result := TestResult{Target: target}

	// Phase 1: DNS Lookup
	result.DNS = testDNS(target, timeout)
	if !result.DNS.Success {
		result.TCP = PhaseResult{Detail: "skipped (DNS failed)"}
		result.TLS = PhaseResult{Detail: "skipped (DNS failed)"}
		return result
	}

	// Phase 2: TCP Connection
	result.TCP = testTCP(target, timeout)
	if !result.TCP.Success {
		result.TLS = PhaseResult{Detail: "skipped (TCP failed)"}
		return result
	}

	// Phase 3: TLS Handshake with SNI
	result.TLS = testTLS(target, timeout)

	return result
}

// testDNS performs DNS resolution for the target host.
func testDNS(target Target, timeout time.Duration) PhaseResult {
	resolver := &net.Resolver{}

	// Append trailing dot to treat as absolute FQDN,
	// bypassing Kubernetes search domain resolution (ndots:5).
	lookupHost := target.Host
	if !strings.HasSuffix(lookupHost, ".") {
		lookupHost = lookupHost + "."
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, lookupHost)
	elapsed := time.Since(start)

	if err != nil {
		return PhaseResult{
			Success:  false,
			Duration: elapsed,
			Detail:   simplifyError(err),
		}
	}

	return PhaseResult{
		Success:  true,
		Duration: elapsed,
		Detail:   strings.Join(addrs, ", "),
	}
}

// testTCP attempts a TCP connection to the target host:port.
func testTCP(target Target, timeout time.Duration) PhaseResult {
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	elapsed := time.Since(start)

	if err != nil {
		return PhaseResult{
			Success:  false,
			Duration: elapsed,
			Detail:   simplifyError(err),
		}
	}
	conn.Close()

	return PhaseResult{
		Success:  true,
		Duration: elapsed,
		Detail:   "connected",
	}
}

// testTLS attempts a TLS handshake with SNI set to the target host.
func testTLS(target Target, timeout time.Duration) PhaseResult {
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))

	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: false,
	})
	elapsed := time.Since(start)

	if err != nil {
		return PhaseResult{
			Success:  false,
			Duration: elapsed,
			Detail:   simplifyError(err),
		}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	tlsVersion := tlsVersionString(state.Version)
	detail := fmt.Sprintf("%s, %s", tlsVersion, tls.CipherSuiteName(state.CipherSuite))

	return PhaseResult{
		Success:  true,
		Duration: elapsed,
		Detail:   detail,
	}
}

// simplifyError extracts a concise error message.
func simplifyError(err error) string {
	msg := err.Error()

	// Extract the most useful part of common net errors
	if strings.Contains(msg, "no such host") {
		return "NXDOMAIN"
	}
	if strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "deadline exceeded") {
		return "timeout"
	}
	if strings.Contains(msg, "connection refused") {
		return "connection refused"
	}
	if strings.Contains(msg, "connection reset") {
		return "connection reset"
	}
	if strings.Contains(msg, "certificate") {
		// Keep certificate errors informative
		if strings.Contains(msg, "unknown authority") {
			return "cert: unknown authority"
		}
		if strings.Contains(msg, "expired") {
			return "cert: expired"
		}
		return "cert error"
	}
	if strings.Contains(msg, "handshake failure") {
		return "TLS handshake failure"
	}

	// Trim common prefixes for readability
	if idx := strings.LastIndex(msg, ": "); idx != -1 {
		return msg[idx+2:]
	}

	return msg
}

// tlsVersionString converts a TLS version constant to a human-readable string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

// printHeader prints the test configuration banner.
func printHeader(targets []Target, timeout time.Duration) {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║         FQDN Filter Tester — Egress Validation          ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("\n  Targets:  %d\n", len(targets))
	fmt.Printf("  Timeout:  %s per phase\n", timeout)
	fmt.Printf("  Phases:   DNS → TCP → TLS/SNI\n\n")
}

// printResults outputs the ASCII table with test results.
func printResults(results []TestResult) {
	// Calculate column widths
	maxHostLen := 4 // "FQDN"
	for _, r := range results {
		if len(r.Target.Host) > maxHostLen {
			maxHostLen = len(r.Target.Host)
		}
	}
	if maxHostLen > 40 {
		maxHostLen = 40
	}

	hostCol := maxHostLen + 2
	portCol := 6
	dnsCol := 16
	tcpCol := 16
	tlsCol := 16
	resultCol := 8

	// Print table header
	printSeparator(hostCol, portCol, dnsCol, tcpCol, tlsCol, resultCol, "┌", "┬", "┐")
	fmt.Printf("│ %-*s│ %-*s│ %-*s│ %-*s│ %-*s│ %-*s│\n",
		hostCol, " FQDN",
		portCol, " PORT",
		dnsCol, " DNS",
		tcpCol, " TCP",
		tlsCol, " TLS/SNI",
		resultCol, " RESULT",
	)
	printSeparator(hostCol, portCol, dnsCol, tcpCol, tlsCol, resultCol, "├", "┼", "┤")

	// Print each result row
	passed := 0
	failed := 0
	for _, r := range results {
		host := r.Target.Host
		if len(host) > maxHostLen {
			host = host[:maxHostLen-1] + "…"
		}

		allPassed := r.DNS.Success && r.TCP.Success && r.TLS.Success
		if allPassed {
			passed++
		} else {
			failed++
		}

		dnsCell := formatPhaseCell(r.DNS)
		tcpCell := formatPhaseCell(r.TCP)
		tlsCell := formatPhaseCell(r.TLS)
		resultCell := formatResultCell(allPassed)

		fmt.Printf("│ %-*s│ %-*s│ %s│ %s│ %s│ %s│\n",
			hostCol, " "+host,
			portCol, fmt.Sprintf(" %d", r.Target.Port),
			padRight(dnsCell, dnsCol),
			padRight(tcpCell, tcpCol),
			padRight(tlsCell, tlsCol),
			padRight(resultCell, resultCol),
		)
	}

	printSeparator(hostCol, portCol, dnsCol, tcpCol, tlsCol, resultCol, "└", "┴", "┘")

	// Summary
	total := passed + failed
	fmt.Printf("\n  Results: %s%d/%d passed%s", colorGreen, passed, total, colorReset)
	if failed > 0 {
		fmt.Printf(" | %s%d/%d failed%s", colorRed, failed, total, colorReset)
	}
	fmt.Printf("\n\n")
}

// formatPhaseCell formats a single phase result for table display.
func formatPhaseCell(p PhaseResult) string {
	if p.Detail == "" && !p.Success {
		return fmt.Sprintf(" %s—%s", colorDim, colorReset)
	}
	if p.Detail != "" && !p.Success && strings.HasPrefix(p.Detail, "skipped") {
		return fmt.Sprintf(" %s—%s", colorDim, colorReset)
	}

	if p.Success {
		return fmt.Sprintf(" %s✅ %dms%s", colorGreen, p.Duration.Milliseconds(), colorReset)
	}
	return fmt.Sprintf(" %s❌ %s%s", colorRed, p.Detail, colorReset)
}

// formatResultCell formats the overall result cell.
func formatResultCell(passed bool) string {
	if passed {
		return fmt.Sprintf(" %s%sPASS%s", colorBold, colorGreen, colorReset)
	}
	return fmt.Sprintf(" %s%sFAIL%s", colorBold, colorRed, colorReset)
}

// printSeparator prints a horizontal table separator line.
func printSeparator(cols ...interface{}) {
	// Last 3 args are left, mid, right characters
	args := cols
	n := len(args)
	left := args[n-3].(string)
	mid := args[n-2].(string)
	right := args[n-1].(string)
	widths := make([]int, n-3)
	for i := 0; i < n-3; i++ {
		widths[i] = args[i].(int)
	}

	fmt.Print(left)
	for i, w := range widths {
		for j := 0; j < w+1; j++ {
			fmt.Print("─")
		}
		if i < len(widths)-1 {
			fmt.Print(mid)
		}
	}
	fmt.Println(right)
}

// padRight pads a string (which may contain ANSI codes) to the given visible width.
func padRight(s string, width int) string {
	visible := visibleLen(s)
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

// visibleLen calculates the visible length of a string, excluding ANSI escape codes.
func visibleLen(s string) int {
	length := 0
	inEscape := false
	for _, r := range s {
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		// Handle multi-byte emoji characters (✅ and ❌ display as width 2 in most terminals)
		if r == '✅' || r == '❌' {
			length += 2
		} else {
			length++
		}
	}
	return length
}
