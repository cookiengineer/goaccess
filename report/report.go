package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cookiengineer/goaccess/types"
)

// ANSI terminal color codes.
const (
	colorRed    = "\033[91m"
	colorGreen  = "\033[92m"
	colorYellow = "\033[93m"
	colorBlue   = "\033[94m"
	colorReset  = "\033[0m"
)

// Report formats and writes output for CLI actions.
type Report struct {
	JSON    bool
	Verbose bool
	Output  io.Writer
}

// NewReport creates a Report. If output is nil, os.Stdout is used.
func NewReport(jsonOutput, verbose bool, output io.Writer) *Report {
	if output == nil {
		output = os.Stdout
	}
	return &Report{
		JSON:    jsonOutput,
		Verbose: verbose,
		Output:  output,
	}
}

func (report *Report) printf(format string, arguments ...interface{}) {
	fmt.Fprintf(report.Output, format, arguments...)
}

// Info prints an informational message.
func (report *Report) Info(format string, arguments ...interface{}) {
	if report.JSON {
		return
	}
	report.printf(format+"\n", arguments...)
}

// Success prints a success message prefixed with [+].
func (report *Report) Success(format string, arguments ...interface{}) {
	if report.JSON {
		return
	}
	message := fmt.Sprintf(format, arguments...)
	report.printf("%s[+]%s %s\n", colorGreen, colorReset, message)
}

// Error prints an error message prefixed with [-].
func (report *Report) Error(format string, arguments ...interface{}) {
	if report.JSON {
		return
	}
	message := fmt.Sprintf(format, arguments...)
	report.printf("%s[-]%s %s\n", colorRed, colorReset, message)
}

// Warning prints a warning message prefixed with [!].
func (report *Report) Warning(format string, arguments ...interface{}) {
	if report.JSON {
		return
	}
	message := fmt.Sprintf(format, arguments...)
	report.printf("%s[!]%s %s\n", colorYellow, colorReset, message)
}

// Status prints a status message prefixed with [*].
func (report *Report) Status(format string, arguments ...interface{}) {
	if !report.Verbose && !report.JSON {
		return
	}
	if report.JSON {
		return
	}
	message := fmt.Sprintf(format, arguments...)
	report.printf("%s[*]%s %s\n", colorBlue, colorReset, message)
}

// Table prints a column-aligned table with headers and rows.
func (report *Report) Table(headers []string, rows [][]string) {
	if report.JSON {
		return
	}
	if len(headers) == 0 || len(rows) == 0 {
		return
	}

	// Calculate column widths
	columnWidths := make([]int, len(headers))
	for index, header := range headers {
		columnWidths[index] = len(header)
	}
	for _, row := range rows {
		for index, cell := range row {
			if index < len(columnWidths) && len(cell) > columnWidths[index] {
				columnWidths[index] = len(cell)
			}
		}
	}

	// Print headers
	var headerLine strings.Builder
	var separatorLine strings.Builder
	for index, width := range columnWidths {
		padding := strings.Repeat(" ", width-len(headers[index]))
		headerLine.WriteString(headers[index])
		headerLine.WriteString(padding)
		separatorLine.WriteString(strings.Repeat("-", width))
		if index < len(columnWidths)-1 {
			headerLine.WriteString("  ")
			separatorLine.WriteString("  ")
		}
	}
	report.printf("%s\n", headerLine.String())
	report.printf("%s\n", separatorLine.String())

	// Print rows
	for _, row := range rows {
		var rowLine strings.Builder
		for index, cell := range row {
			if index >= len(columnWidths) {
				break
			}
			padding := strings.Repeat(" ", columnWidths[index]-len(cell))
			rowLine.WriteString(cell)
			rowLine.WriteString(padding)
			if index < len(columnWidths)-1 {
				rowLine.WriteString("  ")
			}
		}
		report.printf("%s\n", rowLine.String())
	}
}

// KeyValue prints key: value pairs in aligned columns.
func (report *Report) KeyValue(pairs map[string]string) {
	if report.JSON {
		return
	}
	if len(pairs) == 0 {
		return
	}

	maxKeyLength := 0
	for key := range pairs {
		if len(key) > maxKeyLength {
			maxKeyLength = len(key)
		}
	}

	for key, value := range pairs {
		padding := strings.Repeat(" ", maxKeyLength-len(key))
		report.printf("  %s%s : %s\n", key, padding, value)
	}
}

// PrintFingerprint formats a FingerprintResult for display.
func (report *Report) PrintFingerprint(fp *types.FingerprintResult) {
	if report.JSON {
		data, err := json.MarshalIndent(fp, "", "  ")
		if err == nil {
			report.printf("%s\n", data)
		}
		return
	}
	if fp == nil {
		return
	}

	pairs := map[string]string{
		"IP":     fp.IP,
		"Vendor": fp.Vendor,
		"Model":  fp.Model,
		"Firmware": fp.Firmware,
	}

	if fp.MAC != "" {
		pairs["MAC"] = fp.MAC
	}
	if fp.OUI != "" {
		pairs["OUI"] = fp.OUI
	}
	if fp.Confidence > 0 {
		pairs["Confidence"] = fmt.Sprintf("%.1f%%", fp.Confidence*100)
	}

	report.KeyValue(pairs)

	if len(fp.Services) > 0 {
		serviceStrings := make([]string, len(fp.Services))
		for index, port := range fp.Services {
			serviceStrings[index] = fmt.Sprintf("%d", port)
		}
		report.printf("  Services : %s\n", strings.Join(serviceStrings, ", "))
	}
	if len(fp.Hints) > 0 {
		for _, hint := range fp.Hints {
			report.printf("  Hint     : %s\n", hint)
		}
	}
}

// PrintScanResult formats a single ScanResult.
func (report *Report) PrintScanResult(result *types.ScanResult) {
	if result == nil {
		return
	}
	moduleName := result.Module
	if result.Exploit != nil {
		moduleName = result.Exploit.Name
	}

	if report.JSON {
		data, err := json.Marshal(result)
		if err == nil {
			report.printf("%s\n", data)
		}
		return
	}

	if result.Vulnerability != nil && result.Vulnerability.Confirmed {
		report.Success("%s — VULNERABLE — %s", moduleName, result.Vulnerability.Details)
	} else if result.Error != nil {
		report.Error("%s — ERROR: %s", moduleName, result.Error)
	} else if len(result.Credentials) > 0 {
		for _, cred := range result.Credentials {
			report.Success("%s — CREDENTIALS — %s:%s", moduleName, cred.Username, cred.Password)
		}
	} else if !report.Verbose {
		return
	} else {
		report.Status("%s — not vulnerable", moduleName)
	}
}

// PrintScanResultsJSON writes a slice of ScanResults as a JSON array.
// This is used with --json --output to write a complete JSON report.
func (report *Report) PrintScanResultsJSON(results []*types.ScanResult) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		report.Error("JSON marshal error: %s", err)
		return
	}
	report.printf("%s\n", data)
}

// PrintAccessResult formats an AccessResult for display.
func (report *Report) PrintAccessResult(result *types.AccessResult) {
	if report.JSON {
		data, err := json.MarshalIndent(result, "", "  ")
		if err == nil {
			report.printf("%s\n", data)
		}
		return
	}
	if result == nil {
		return
	}

	if result.Success {
		report.Success("Access achieved for %s", result.Target)
	} else {
		report.Error("Access failed for %s", result.Target)
	}

	if len(result.Credentials) > 0 {
		report.Success("Recovered credentials:")
		for _, cred := range result.Credentials {
			report.printf("  %s:%s on %s (port %d)\n", cred.Username, cred.Password, cred.Service, cred.Port)
		}
	}

	if result.Shell != nil {
		report.Success("Shell session established: %s (%s:%d)", result.Shell.Type, result.Shell.Host, result.Shell.Port)
	}

	for _, step := range result.Steps {
		status := "OK"
		if !step.Success {
			status = "FAIL"
		}
		report.Status("Step %s: %s — %s", step.Step.String(), status, step.Detail)
	}
}

// WriteJSON writes an arbitrary value as indented JSON.
func (report *Report) WriteJSON(value interface{}) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		report.Error("JSON marshal error: %s", err)
		return
	}
	report.printf("%s\n", data)
}
