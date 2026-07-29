package report

import (
	"bytes"
	"testing"

	"github.com/cookiengineer/goaccess/types"
)

func TestNewReport_Defaults(t *testing.T) {
	report := NewReport(false, false, nil)
	if report.JSON {
		t.Error("JSON should default to false")
	}
	if report.Verbose {
		t.Error("Verbose should default to false")
	}
	if report.Output == nil {
		t.Error("Output should not be nil")
	}
}

func TestInfo(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)
	report.Info("test %s", "message")
	output := buffer.String()
	if output != "test message\n" {
		t.Errorf("Info() output = %q, want %q", output, "test message\n")
	}
}

func TestInfo_JSONSuppressed(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(true, false, &buffer)
	report.Info("should not appear")
	if buffer.Len() > 0 {
		t.Error("Info() should not write when JSON is enabled")
	}
}

func TestSuccess(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)
	report.Success("exploit worked")
	output := buffer.String()
	if output == "" {
		t.Error("Success() should produce output")
	}
	// Verify it contains the [+] marker
	if !bytes.Contains(buffer.Bytes(), []byte("[+]")) {
		t.Error("Success() should contain [+] marker")
	}
}

func TestError(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)
	report.Error("something failed")
	if !bytes.Contains(buffer.Bytes(), []byte("[-]")) {
		t.Error("Error() should contain [-] marker")
	}
}

func TestWarning(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)
	report.Warning("be careful")
	if !bytes.Contains(buffer.Bytes(), []byte("[!]")) {
		t.Error("Warning() should contain [!] marker")
	}
}

func TestStatus_VerboseShown(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, true, &buffer)
	report.Status("progress update")
	if !bytes.Contains(buffer.Bytes(), []byte("[*]")) {
		t.Error("Status() verbose should contain [*] marker")
	}
}

func TestStatus_NonVerboseSuppressed(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)
	report.Status("should not appear")
	if buffer.Len() > 0 {
		t.Error("Status() should not write when verbose is disabled")
	}
}

func TestTable(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)

	report.Table(
		[]string{"Name", "Vendor", "Models"},
		[][]string{
			{"D-Link RCE", "dlink", "DIR-300, DIR-600"},
			{"TP-Link RCE", "tplink", "Archer C2"},
		},
	)

	output := buffer.String()
	if !bytes.Contains(buffer.Bytes(), []byte("Name")) {
		t.Error("Table should contain header")
	}
	if !bytes.Contains(buffer.Bytes(), []byte("dlink")) {
		t.Error("Table should contain row data")
	}
	if len(output) < 20 {
		t.Error("Table output too short")
	}
}

func TestTable_Empty(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)

	report.Table(nil, nil)
	report.Table([]string{}, [][]string{})
	report.Table([]string{"Col"}, [][]string{})

	if buffer.Len() > 0 {
		t.Error("Empty table should produce no output")
	}
}

func TestKeyValue(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)
	report.KeyValue(map[string]string{
		"Vendor": "dlink",
		"Model":  "DIR-300",
	})
	output := buffer.String()
	if !bytes.Contains(buffer.Bytes(), []byte("Vendor")) {
		t.Error("KeyValue should contain key")
	}
	if !bytes.Contains(buffer.Bytes(), []byte("dlink")) {
		t.Error("KeyValue should contain value")
	}
	if len(output) < 10 {
		t.Error("KeyValue output too short")
	}
}

func TestPrintFingerprint(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)
	fp := &types.FingerprintResult{
		IP:         "192.168.1.1",
		MAC:        "00:50:BA:12:34:56",
		OUI:        "D-Link",
		Vendor:     "dlink",
		Model:      "DIR-300",
		Services:   []int{80, 443},
		Confidence: 0.85,
	}
	report.PrintFingerprint(fp)
	output := buffer.String()
	if !bytes.Contains(buffer.Bytes(), []byte("dlink")) {
		t.Errorf("Fingerprint output missing vendor: %s", output)
	}
}

func TestPrintFingerprint_JSON(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(true, false, &buffer)
	fp := &types.FingerprintResult{IP: "10.0.0.1", Vendor: "test"}
	report.PrintFingerprint(fp)
	if !bytes.Contains(buffer.Bytes(), []byte(`"10.0.0.1"`)) {
		t.Error("JSON fingerprint should contain IP")
	}
}

func TestPrintScanResult(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)

	result := &types.ScanResult{
		Exploit: &types.Info{Name: "Test Exploit"},
		Vulnerability: &types.VulnResult{
			Confirmed: true,
			Details:   "target is vulnerable",
		},
	}
	report.PrintScanResult(result)
	if !bytes.Contains(buffer.Bytes(), []byte("VULNERABLE")) {
		t.Error("Vulnerable result should show VULNERABLE")
	}
}

func TestWriteJSON(t *testing.T) {
	var buffer bytes.Buffer
	report := NewReport(false, false, &buffer)
	data := map[string]string{"key": "value"}
	report.WriteJSON(data)
	if !bytes.Contains(buffer.Bytes(), []byte(`"key"`)) {
		t.Error("WriteJSON should contain key")
	}
	if !bytes.Contains(buffer.Bytes(), []byte(`"value"`)) {
		t.Error("WriteJSON should contain value")
	}
}
