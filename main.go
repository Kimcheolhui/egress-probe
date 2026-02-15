package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort    = 443
	defaultTimeout = 5 * time.Second
)

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

type Target struct {
	Host      string
	Port      int
	ExpectErr bool // true = this target should be blocked (DENY)
}

type PhaseResult struct {
	Success  bool
	Duration time.Duration
	Detail   string
}

type TestResult struct {
	Target  Target
	DNS     PhaseResult
	TCP     PhaseResult
	TLS     PhaseResult
	Passed  bool // true = outcome matches expectation
	Blocked bool // true = connectivity failed at some phase
}

func main() {
	targets, timeout := parseConfig()

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no targets specified.\n")
		fmt.Fprintf(os.Stderr, "Set ALLOW_TARGETS and/or DENY_TARGETS environment variables.\n")
		fmt.Fprintf(os.Stderr, "Example: ALLOW_TARGETS=\"mcr.microsoft.com:443\" DENY_TARGETS=\"google.com\" %s\n", os.Args[0])
		os.Exit(1)
	}

	jsonMode := os.Getenv("OUTPUT") == "json"

	if !jsonMode {
		printHeader(targets, timeout)
	}

	warmupDur := warmupDNS(timeout)
	if !jsonMode && warmupDur > time.Second {
		fmt.Printf("  %sDNS warm-up: %dms (first-packet penalty absorbed)%s\n\n",
			colorDim, warmupDur.Milliseconds(), colorReset)
	}

	results := runTests(targets, timeout)

	for i := range results {
		blocked := !results[i].DNS.Success || !results[i].TCP.Success || !results[i].TLS.Success
		results[i].Blocked = blocked
		if results[i].Target.ExpectErr {
			results[i].Passed = blocked // DENY target: pass if blocked
		} else {
			results[i].Passed = !blocked // ALLOW target: pass if reachable
		}
	}

	if jsonMode {
		printJSON(results, timeout)
	} else {
		printResults(results)
	}

	for _, r := range results {
		if !r.Passed {
			os.Exit(1)
		}
	}
}

func parseConfig() ([]Target, time.Duration) {
	timeout := defaultTimeout
	if t := os.Getenv("TIMEOUT"); t != "" {
		if sec, err := strconv.Atoi(t); err == nil && sec > 0 {
			timeout = time.Duration(sec) * time.Second
		}
	}

	var targets []Target

	if raw := os.Getenv("ALLOW_TARGETS"); raw != "" {
		targets = append(targets, parseTargetList(raw, false)...)
	}
	if raw := os.Getenv("DENY_TARGETS"); raw != "" {
		targets = append(targets, parseTargetList(raw, true)...)
	}

	// Backwards compatibility: TARGETS treated as ALLOW_TARGETS
	if raw := os.Getenv("TARGETS"); raw != "" && len(targets) == 0 {
		targets = append(targets, parseTargetList(raw, false)...)
	}

	return targets, timeout
}

func parseTargetList(raw string, expectErr bool) []Target {
	var targets []Target
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		t := parseTarget(entry)
		t.ExpectErr = expectErr
		targets = append(targets, t)
	}
	return targets
}

func parseTarget(s string) Target {
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

	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}

	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Target{Host: s, Port: inferredPort}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		port = inferredPort
	}
	return Target{Host: host, Port: port}
}

// warmupDNS sends a throwaway DNS query to absorb the first-packet latency
// penalty caused by network path initialization (conntrack, DNAT, etc.).
// In many Kubernetes clusters, the very first UDP packet from a new Pod is
// dropped, causing a ~5s retry delay. This warm-up absorbs that penalty so
// actual test results are not affected.
func warmupDNS(timeout time.Duration) time.Duration {
	resolver := &net.Resolver{PreferGo: true}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	resolver.LookupIP(ctx, "ip4", "kubernetes.default.svc.cluster.local.")
	return time.Since(start)
}

// runTests runs DNS lookups sequentially to avoid the Kubernetes conntrack
// race condition on concurrent UDP queries, then runs TCP/TLS in parallel.
func runTests(targets []Target, timeout time.Duration) []TestResult {
	results := make([]TestResult, len(targets))

	for i, t := range targets {
		results[i] = TestResult{Target: t}
		results[i].DNS = testDNS(t, timeout)
	}

	var wg sync.WaitGroup
	for i := range results {
		if !results[i].DNS.Success {
			results[i].TCP = PhaseResult{Detail: "skipped (DNS failed)"}
			results[i].TLS = PhaseResult{Detail: "skipped (DNS failed)"}
			continue
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx].TCP = testTCP(targets[idx], timeout)
			if !results[idx].TCP.Success {
				results[idx].TLS = PhaseResult{Detail: "skipped (TCP failed)"}
				return
			}
			results[idx].TLS = testTLS(targets[idx], timeout)
		}(i)
	}

	wg.Wait()
	return results
}

func testDNS(target Target, timeout time.Duration) PhaseResult {
	if net.ParseIP(target.Host) != nil {
		return PhaseResult{
			Success:  true,
			Duration: 0,
			Detail:   target.Host + " (literal)",
		}
	}

	resolver := &net.Resolver{PreferGo: true}

	lookupHost := target.Host
	if !strings.HasSuffix(lookupHost, ".") {
		lookupHost = lookupHost + "."
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ips, err := resolver.LookupIP(ctx, "ip4", lookupHost)
	elapsed := time.Since(start)

	if err != nil {
		return PhaseResult{
			Success:  false,
			Duration: elapsed,
			Detail:   simplifyError(err),
		}
	}

	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = ip.String()
	}

	return PhaseResult{
		Success:  true,
		Duration: elapsed,
		Detail:   strings.Join(addrs, ", "),
	}
}

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

func simplifyError(err error) string {
	msg := err.Error()

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

	if idx := strings.LastIndex(msg, ": "); idx != -1 {
		return msg[idx+2:]
	}

	return msg
}

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

type jsonOutput struct {
	Summary jsonSummary `json:"summary"`
	Results []jsonResult `json:"results"`
}

type jsonSummary struct {
	Total   int    `json:"total"`
	Allow   int    `json:"allow"`
	Deny    int    `json:"deny"`
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	OK      bool   `json:"ok"`
	Timeout string `json:"timeout"`
}

type jsonPhase struct {
	Success    bool   `json:"success"`
	DurationMs int64  `json:"duration_ms"`
	Detail     string `json:"detail"`
}

type jsonResult struct {
	Host    string    `json:"host"`
	Port    int       `json:"port"`
	Type    string    `json:"type"`
	DNS     jsonPhase `json:"dns"`
	TCP     jsonPhase `json:"tcp"`
	TLS     jsonPhase `json:"tls"`
	Passed  bool      `json:"passed"`
	Blocked bool      `json:"blocked"`
}

func toJSONPhase(p PhaseResult) jsonPhase {
	return jsonPhase{
		Success:    p.Success,
		DurationMs: p.Duration.Milliseconds(),
		Detail:     p.Detail,
	}
}

func printJSON(results []TestResult, timeout time.Duration) {
	var allowCount, denyCount, passed, failed int
	jResults := make([]jsonResult, len(results))

	for i, r := range results {
		typ := "allow"
		if r.Target.ExpectErr {
			typ = "deny"
			denyCount++
		} else {
			allowCount++
		}
		if r.Passed {
			passed++
		} else {
			failed++
		}
		jResults[i] = jsonResult{
			Host:    r.Target.Host,
			Port:    r.Target.Port,
			Type:    typ,
			DNS:     toJSONPhase(r.DNS),
			TCP:     toJSONPhase(r.TCP),
			TLS:     toJSONPhase(r.TLS),
			Passed:  r.Passed,
			Blocked: r.Blocked,
		}
	}

	out := jsonOutput{
		Summary: jsonSummary{
			Total:   len(results),
			Allow:   allowCount,
			Deny:    denyCount,
			Passed:  passed,
			Failed:  failed,
			OK:      failed == 0,
			Timeout: timeout.String(),
		},
		Results: jResults,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func printHeader(targets []Target, timeout time.Duration) {
	allowCount := 0
	denyCount := 0
	for _, t := range targets {
		if t.ExpectErr {
			denyCount++
		} else {
			allowCount++
		}
	}

	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║            Egress Probe — Egress Validation              ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("\n  Targets:  %d (%s%d allow%s / %s%d deny%s)\n", len(targets),
		colorGreen, allowCount, colorReset,
		colorYellow, denyCount, colorReset)
	fmt.Printf("  Timeout:  %s per phase\n", timeout)
	fmt.Printf("  Phases:   DNS → TCP → TLS/SNI\n\n")
}

func printResults(results []TestResult) {
	var allow, deny []TestResult
	for _, r := range results {
		if r.Target.ExpectErr {
			deny = append(deny, r)
		} else {
			allow = append(allow, r)
		}
	}

	maxHostLen := 4
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
	cols := []int{hostCol, portCol, dnsCol, tcpCol, tlsCol, resultCol}

	totalWidth := 0
	for _, w := range cols {
		totalWidth += w + 1
	}
	totalWidth += 5

	printSeparator(cols, "┌", "┬", "┐")
	fmt.Printf("│ %-*s│ %-*s│ %-*s│ %-*s│ %-*s│ %-*s│\n",
		hostCol, " FQDN",
		portCol, " PORT",
		dnsCol, " DNS",
		tcpCol, " TCP",
		tlsCol, " TLS/SNI",
		resultCol, " RESULT",
	)

	ok := 0
	ng := 0

	printRow := func(r TestResult) {
		host := r.Target.Host
		if len(host) > maxHostLen {
			host = host[:maxHostLen-1] + "…"
		}
		if r.Passed {
			ok++
		} else {
			ng++
		}

		dnsCell := formatPhaseCell(r.DNS)
		tcpCell := formatPhaseCell(r.TCP)
		tlsCell := formatPhaseCell(r.TLS)

		var resultCell string
		if r.Passed {
			resultCell = fmt.Sprintf(" %s%sOK%s", colorBold, colorGreen, colorReset)
		} else {
			resultCell = fmt.Sprintf(" %s%sFAIL%s", colorBold, colorRed, colorReset)
		}

		fmt.Printf("│ %-*s│ %-*s│ %s│ %s│ %s│ %s│\n",
			hostCol, " "+host,
			portCol, fmt.Sprintf(" %d", r.Target.Port),
			padRight(dnsCell, dnsCol),
			padRight(tcpCell, tcpCol),
			padRight(tlsCell, tlsCol),
			padRight(resultCell, resultCol),
		)
	}

	if len(allow) > 0 {
		printSeparator(cols, "├", "┴", "┤")
		label := fmt.Sprintf("  %s%sALLOW%s — should be reachable", colorBold, colorGreen, colorReset)
		printSectionLabel(label, totalWidth)
		printSeparator(cols, "├", "┬", "┤")
		for _, r := range allow {
			printRow(r)
		}
	}

	if len(deny) > 0 {
		printSeparator(cols, "├", "┴", "┤")
		label := fmt.Sprintf("  %s%sDENY%s  — should be blocked", colorBold, colorYellow, colorReset)
		printSectionLabel(label, totalWidth)
		printSeparator(cols, "├", "┬", "┤")
		for _, r := range deny {
			printRow(r)
		}
	}

	printSeparator(cols, "└", "┴", "┘")

	total := ok + ng
	fmt.Printf("\n  Results: %s%d/%d OK%s", colorGreen, ok, total, colorReset)
	if ng > 0 {
		fmt.Printf(" | %s%d/%d FAIL%s", colorRed, ng, total, colorReset)
	}
	fmt.Printf("\n\n")
}

func printSectionLabel(text string, totalWidth int) {
	fmt.Printf("│%s│\n", padRight(text, totalWidth))
}

func formatPhaseCell(p PhaseResult) string {
	if !p.Success && (p.Detail == "" || strings.HasPrefix(p.Detail, "skipped")) {
		return fmt.Sprintf(" %s—%s", colorDim, colorReset)
	}

	if p.Success {
		return fmt.Sprintf(" %s✅ %dms%s", colorGreen, p.Duration.Milliseconds(), colorReset)
	}
	return fmt.Sprintf(" %s❌ %s%s", colorRed, p.Detail, colorReset)
}

func printSeparator(widths []int, left, mid, right string) {
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

func padRight(s string, width int) string {
	visible := visibleLen(s)
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

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
		if r == '✅' || r == '❌' {
			length += 2
		} else {
			length++
		}
	}
	return length
}
