package main

import (
	"fmt"
	"os"

	"github.com/byteoverride/desynctrace/internal/client"
	"github.com/byteoverride/desynctrace/internal/detectors"
	"github.com/byteoverride/desynctrace/internal/reporting"
	"github.com/byteoverride/desynctrace/internal/vectors"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

var (
	targetURL string
	proxyURL  string
	threads   int
	cookie    string
)

var scanCmd = &cobra.Command{
	Use:   "scan [url]",
	Short: "Scan a target for HTTP smuggling vulnerabilities",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetURL = args[0]
		runScan()
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&proxyURL, "proxy", "p", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	scanCmd.Flags().StringVar(&cookie, "cookie", "", "Session cookie (e.g., 'session=xyz')")
	scanCmd.Flags().IntVarP(&threads, "threads", "t", 10, "Number of concurrent threads")

	viper.BindPFlag("proxy", scanCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("cookie", scanCmd.Flags().Lookup("cookie"))
	viper.BindPFlag("threads", scanCmd.Flags().Lookup("threads"))
}

func runScan() {
	fmt.Printf("Starting scan against %s\n", targetURL)

	// Headers map
	headers := make(map[string]string)
	if cookie != "" {
		headers["Cookie"] = cookie
	}

	// 1. Initialize Client
	c, err := client.NewFastHTTPClient(true, proxyURL) // Insecure by default for scanning? Or flag it
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		os.Exit(1)
	}

	// 2. Fingerprint
	color.Cyan("[*] Fingerprinting server...")
	fp, err := detectors.FingerprintServer(c, targetURL)
	if err != nil {
		color.Red("[-] Fingerprinting failed: %v\n", err)
	} else {
		color.Green("[+] Server: %s\n", fp.ServerHeader)
		if fp.PoweredBy != "" {
			color.Green("[+] Powered By: %s\n", fp.PoweredBy)
		}
	}

	// 3. Initialize Detectors
	blindDetector := detectors.NewBlindDetector(c, headers)
	poisonDetector := detectors.NewPoisoningDetector(c, headers)

	// 4. Initialize Vectors
	vecs := []vectors.SmugglingVector{
		vectors.NewCLTEVector(),
		vectors.NewTECLVector(),
		vectors.NewH2Vector(),
		vectors.NewTETEVector(),
		vectors.NewCL0Vector(),
		vectors.NewH2CRLFVector(),
	}

	// 5. Run Scan
	report := reporting.NewReport(targetURL)

	p := mpb.New(mpb.WithWidth(64))
	bar := p.AddBar(int64(len(vecs)),
		mpb.PrependDecorators(
			decor.Name("Scanning Vectors", decor.WC{W: len("Scanning Vectors") + 1}),
			decor.CountersNoUnit("%d / %d", decor.WCSyncWidth),
		),
		mpb.AppendDecorators(
			decor.Percentage(decor.WCSyncSpace),
		),
	)

	for _, v := range vecs {
		// fmt.Printf("[*] Testing vector: %s\n", v.Name()) // Conflict with progress bar

		// Blind Check
		res, err := blindDetector.Detect(targetURL, v)
		if err != nil {
			// logging error might mess up bar, use log or silent
		} else if res.IsVulnerable {
			report.AddFinding(res)

			// If blind check passed, try poisoning verification
			resP, err := poisonDetector.Detect(targetURL, v)
			if err == nil && resP.IsVulnerable {
				report.AddFinding(resP)
			}
		}
		bar.Increment()
	}
	p.Wait()

	// 6. Save Report
	report.PrintSummary()
	err = report.SaveToFile("desynctrace_report.json")
	if err != nil {
		fmt.Printf("Error saving report: %v\n", err)
	} else {
		fmt.Println("[+] Report saved to desynctrace_report.json")
	}
}
