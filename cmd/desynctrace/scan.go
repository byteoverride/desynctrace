package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/byteoverride/desynctrace/internal/client"
	"github.com/byteoverride/desynctrace/internal/detectors"
	"github.com/byteoverride/desynctrace/internal/reporting"
	"github.com/byteoverride/desynctrace/internal/vectors"
	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

var (
	targetURL   string
	proxyURL    string
	threads     int
	cookie      string
	safeMode    bool
	outputFile  string
	outputFmt   string
	targetsFile string
	pathsFile   string
	delay       int
	maxAttempts int
	skipH2       bool
	vectorFilter string
	showTraffic  bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [url]",
	Short: "Scan a target for HTTP smuggling vulnerabilities",
	Long: `Scan a target URL for HTTP request smuggling vulnerabilities using
multiple detection techniques:

  - Differential timing analysis (safe, non-intrusive)
  - Connection poisoning confirmation (intrusive, proves exploitability)
  - Server fingerprinting with smart vector prioritization

Supports CL.TE, TE.CL, TE.TE, CL.0, H2.CL, H2.TE, H2.CRLF, Double-CL,
Chunk Extension abuse, CL formatting tricks, HTTP/0.9 confusion,
WebSocket smuggling, and more.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			targetURL = args[0]
		}
		if targetURL == "" && targetsFile == "" {
			fmt.Println("Error: provide a target URL or use --targets")
			os.Exit(1)
		}
		if targetsFile != "" {
			runMultiTargetScan()
		} else {
			runScan(targetURL)
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&proxyURL, "proxy", "p", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	scanCmd.Flags().StringVar(&cookie, "cookie", "", "Session cookie (e.g., 'session=xyz')")
	scanCmd.Flags().IntVarP(&threads, "threads", "t", 5, "Concurrent threads per target")
	scanCmd.Flags().BoolVar(&safeMode, "safe", false, "Safe mode: timing detection only, no connection poisoning")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: desynctrace_report.json)")
	scanCmd.Flags().StringVarP(&outputFmt, "format", "f", "json", "Output format: json, markdown, text")
	scanCmd.Flags().StringVar(&targetsFile, "targets", "", "File with target URLs (one per line)")
	scanCmd.Flags().StringVar(&pathsFile, "paths", "", "File with paths to test (one per line)")
	scanCmd.Flags().IntVar(&delay, "delay", 0, "Delay between requests in milliseconds")
	scanCmd.Flags().IntVar(&maxAttempts, "attempts", 5, "Number of attempts per detection probe")
	scanCmd.Flags().BoolVar(&skipH2, "skip-h2", false, "Skip HTTP/2 vectors")
	scanCmd.Flags().StringVar(&vectorFilter, "vectors", "", "Comma-separated vector types to test (e.g., CL.TE,TE.CL)")
	scanCmd.Flags().BoolVar(&showTraffic, "show-traffic", false, "Print raw request/response bytes for each probe")

	viper.BindPFlag("proxy", scanCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("cookie", scanCmd.Flags().Lookup("cookie"))
	viper.BindPFlag("threads", scanCmd.Flags().Lookup("threads"))
}

func runMultiTargetScan() {
	f, err := os.Open(targetsFile)
	if err != nil {
		color.Red("[-] Failed to open targets file: %v", err)
		os.Exit(1)
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	color.Cyan("[*] Loaded %d targets\n", len(targets))
	for i, t := range targets {
		color.Cyan("\n[%d/%d] Scanning %s\n", i+1, len(targets), t)
		runScan(t)
	}
}

func runScan(target string) {
	startTime := time.Now()

	// Headers map
	headers := make(map[string]string)
	if cookie != "" {
		headers["Cookie"] = cookie
	}

	// Initialize high-level client for fingerprinting
	c, err := client.NewFastHTTPClient(true, proxyURL)
	if err != nil {
		color.Red("[-] Error creating client: %v", err)
		return
	}

	// Fingerprint
	color.Cyan("[*] Fingerprinting server...")
	fp, err := detectors.FingerprintServer(c, target)
	if err != nil {
		color.Yellow("[!] Fingerprinting failed: %v", err)
		fp = &detectors.ServerFingerprint{}
	} else {
		color.Green("[+] %s", fp.Summary())
	}

	// Select vectors
	allVecs := vectors.AllVectors()

	// Filter by user request
	if vectorFilter != "" {
		allVecs = filterVectors(allVecs, vectorFilter)
	}
	if skipH2 || !fp.SupportsH2 {
		allVecs = filterOutH2(allVecs)
	}

	// Prioritize based on fingerprint
	allVecs = detectors.PrioritizeVectors(fp, allVecs)

	color.Cyan("[*] Testing %d vector classes", len(allVecs))

	// Initialize detectors
	timingDetector := detectors.NewTimingDetector(headers)
	timingDetector.Attempts = maxAttempts

	if showTraffic {
		timingDetector.OnTraffic = makeTrafficLogger()
	}

	var confirmDetector *detectors.ConfirmationDetector
	if !safeMode {
		confirmDetector = detectors.NewConfirmationDetector(headers)
		confirmDetector.Attempts = 3
		if showTraffic {
			confirmDetector.OnTraffic = makeTrafficLogger()
		}
	}

	// Load additional paths
	paths := []string{""} // empty = use target URL as-is
	if pathsFile != "" {
		paths = loadPaths(pathsFile)
	}

	// Report
	report := reporting.NewReport(target)
	report.Fingerprint = fp.Summary()

	// Progress bar
	totalWork := len(allVecs) * len(paths)
	p := mpb.New(mpb.WithWidth(64))
	bar := p.AddBar(int64(totalWork),
		mpb.PrependDecorators(
			decor.Name("Scanning", decor.WC{W: len("Scanning") + 1}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncWidth),
		),
		mpb.AppendDecorators(
			decor.Percentage(decor.WCSyncSpace),
		),
	)

	// Concurrent scanning with goroutine pool
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, v := range allVecs {
		for _, extraPath := range paths {
			wg.Add(1)
			sem <- struct{}{}

			go func(vec vectors.SmugglingVector, pathSuffix string) {
				defer wg.Done()
				defer func() { <-sem }()
				defer bar.Increment()

				scanTarget := target
				if pathSuffix != "" {
					scanTarget = strings.TrimRight(target, "/") + "/" + strings.TrimLeft(pathSuffix, "/")
				}

				if delay > 0 {
					time.Sleep(time.Duration(delay) * time.Millisecond)
				}

				// Phase 1: Timing detection (always safe)
				result, err := timingDetector.Detect(scanTarget, vec)
				if err != nil {
					log.Debug().Err(err).Str("vector", string(vec.Type())).Msg("timing detection error")
					return
				}

				if result.IsVulnerable {
					mu.Lock()
					report.AddFinding(result)
					mu.Unlock()

					if !safeMode && confirmDetector != nil {
						// Phase 2: Confirmation via poisoning
						confirmed, err := confirmDetector.Detect(scanTarget, vec)
						if err == nil && confirmed.IsVulnerable {
							mu.Lock()
							report.AddFinding(confirmed)
							mu.Unlock()
						}
					}
				}
			}(v, extraPath)
		}
	}

	wg.Wait()
	p.Wait()

	// Report
	report.Duration = time.Since(startTime).String()
	report.PrintSummary()

	// Save report
	outFile := outputFile
	if outFile == "" {
		outFile = "desynctrace_report." + outputFmt
	}

	var saveErr error
	switch outputFmt {
	case "markdown", "md":
		saveErr = report.SaveMarkdown(outFile)
	case "text", "txt":
		saveErr = report.SaveText(outFile)
	default:
		saveErr = report.SaveToFile(outFile)
	}

	if saveErr != nil {
		color.Red("[-] Error saving report: %v", saveErr)
	} else {
		color.Green("[+] Report saved to %s", outFile)
	}
}

func filterVectors(vecs []vectors.SmugglingVector, filter string) []vectors.SmugglingVector {
	parts := strings.Split(filter, ",")
	allowed := make(map[string]bool)
	for _, p := range parts {
		allowed[strings.TrimSpace(p)] = true
	}

	var filtered []vectors.SmugglingVector
	for _, v := range vecs {
		if allowed[string(v.Type())] {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func filterOutH2(vecs []vectors.SmugglingVector) []vectors.SmugglingVector {
	var filtered []vectors.SmugglingVector
	for _, v := range vecs {
		switch v.Type() {
		case vectors.H2CL, vectors.H2TE, vectors.H2CRLF, vectors.H2Pseudo, vectors.H2Tunnel:
			continue
		}
		filtered = append(filtered, v)
	}
	return filtered
}

func loadPaths(filename string) []string {
	f, err := os.Open(filename)
	if err != nil {
		color.Yellow("[!] Could not open paths file: %v", err)
		return []string{""}
	}
	defer f.Close()

	var paths []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			paths = append(paths, line)
		}
	}
	if len(paths) == 0 {
		return []string{""}
	}
	return paths
}

func makeTrafficLogger() detectors.TrafficLogger {
	return func(label string, data []byte, resp *client.RawHTTPResponse, elapsed time.Duration) {
		color.Yellow("\n--- [%s] ---", label)
		if elapsed > 0 {
			fmt.Printf("  Elapsed: %v\n", elapsed)
		}
		if len(data) > 0 {
			color.Cyan("  >> REQUEST (%d bytes):", len(data))
			printTrafficBytes(data, ">")
		}
		if resp != nil && resp.StatusCode > 0 {
			if resp.StatusCode >= 400 {
				color.Red("  << RESPONSE: %d %s", resp.StatusCode, resp.StatusText)
			} else {
				color.Green("  << RESPONSE: %d %s", resp.StatusCode, resp.StatusText)
			}
			if len(resp.Body) > 0 {
				preview := string(resp.Body)
				if len(preview) > 200 {
					preview = preview[:200] + "..."
				}
				fmt.Printf("  Body: %s\n", preview)
			}
		} else if resp != nil && resp.Error != "" {
			color.Red("  << ERROR: %s", resp.Error)
		}
	}
}

func printTrafficBytes(data []byte, prefix string) {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i > 15 {
			fmt.Printf("  %s ... (%d more lines)\n", prefix, len(lines)-i)
			break
		}
		fmt.Printf("  %s %s\n", prefix, line)
	}
}
