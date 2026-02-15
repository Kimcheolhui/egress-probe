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
	Host string
	Port int
}

type PhaseResult struct {
	Success  bool
	Duration time.Duration
	Detail   string
}

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

	for _, r := range results {
		if !r.DNS.Success || !r.TCP.Success || !r.TLS.Success {
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

func printHeader(targets []Target, timeout time.Duration) {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║         FQDN Filter Tester — Egress Validation          ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("\n  Targets:  %d\n", len(targets))
	fmt.Printf("  Timeout:  %s per phase\n", timeout)
	fmt.Printf("  Phases:   DNS → TCP → TLS/SNI\n\n")
}

func printResults(results []TestResult) {
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

	total := passed + failed
	fmt.Printf("\n  Results: %s%d/%d passed%s", colorGreen, passed, total, colorReset)
	if failed > 0 {
		fmt.Printf(" | %s%d/%d failed%s", colorRed, failed, total, colorReset)
	}
	fmt.Printf("\n\n")
}

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

func formatResultCell(passed bool) string {
	if passed {
		return fmt.Sprintf(" %s%sPASS%s", colorBold, colorGreen, colorReset)
	}
	return fmt.Sprintf(" %s%sFAIL%s", colorBold, colorRed, colorReset)
}

func printSeparator(cols ...interface{}) {
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
