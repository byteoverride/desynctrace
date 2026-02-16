package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/byteoverride/desynctrace/internal/detectors"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
)

type Report struct {
	Target    string                       `json:"target"`
	StartTime time.Time                    `json:"start_time"`
	Duration  string                       `json:"duration"`
	Findings  []*detectors.DetectionResult `json:"findings"`
}

func NewReport(target string) *Report {
	return &Report{
		Target:    target,
		StartTime: time.Now(),
		Findings:  []*detectors.DetectionResult{},
	}
}

func (r *Report) AddFinding(finding *detectors.DetectionResult) {
	r.Findings = append(r.Findings, finding)
}

func (r *Report) GenerateJSON() ([]byte, error) {
	r.Duration = time.Since(r.StartTime).String()
	return json.MarshalIndent(r, "", "  ")
}

func (r *Report) SaveToFile(filename string) error {
	data, err := r.GenerateJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func (r *Report) PrintSummary() {
	c := color.New(color.FgCyan, color.Bold)
	c.Printf("\nSCAN REPORT for %s\n", r.Target)
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight) // Prettier table style
	t.AppendHeader(table.Row{"Vector", "Confidence", "Evidence"})

	if len(r.Findings) == 0 {
		color.Green("No vulnerabilities found.\n")
	} else {
		for _, f := range r.Findings {
			t.AppendRow(table.Row{
				color.RedString(string(f.Vector)), // Fixed field name
				color.YellowString(fmt.Sprintf("%d%%", f.Confidence)),
				f.Evidence,
			})
		}
		t.Render()
	}
	fmt.Println("==================================================")
}
