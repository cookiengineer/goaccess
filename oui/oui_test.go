package oui

import (
	"testing"
)

func TestLookup_DLink(t *testing.T) {
	result := Lookup("00:50:BA:12:34:56")
	if result == "" {
		t.Error("Lookup(00:50:BA:12:34:56) returned empty string")
	}
	if result != "D-Link" && result != "D-Link Corporation" && result != "D-Link International" && result != "D-Link Systems" {
		t.Logf("Lookup result: %q (acceptable if D-Link variant)", result)
	}
}

func TestLookup_Cisco(t *testing.T) {
	result := Lookup("CC:46:D6:12:34:56")
	if result == "" {
		t.Error("Lookup(CC:46:D6:12:34:56) returned empty")
	}
}

func TestLookup_Huawei(t *testing.T) {
	result := Lookup("48:AD:08:12:34:56")
	if result == "" {
		t.Error("Lookup(48:AD:08:12:34:56) returned empty")
	}
}

func TestLookup_VariousFormats(t *testing.T) {
	formats := []string{
		"00:50:BA:12:34:56",
		"00-50-BA-12-34-56",
		"0050BA123456",
		"00.50.BA.12.34.56",
	}

	for _, format := range formats {
		result := Lookup(format)
		if result == "" {
			t.Errorf("Lookup(%q) returned empty", format)
		}
	}
}

func TestLookup_ShortMAC(t *testing.T) {
	result := Lookup("00:50")
	if result != "" {
		t.Errorf("Lookup(00:50) should return empty for short MAC, got %q", result)
	}
}

func TestLookup_EmptyMAC(t *testing.T) {
	result := Lookup("")
	if result != "" {
		t.Errorf("Lookup() should return empty, got %q", result)
	}
}

func TestLookup_UnknownMAC(t *testing.T) {
	result := Lookup("FF:FF:FF:12:34:56")
	if result != "" {
		t.Logf("Lookup(FF:FF:FF) matched unexpectedly: %q", result)
	}
}

func TestLookupPrefixes(t *testing.T) {
	prefixes := LookupPrefixes("dlink")
	if len(prefixes) == 0 {
		t.Error("LookupPrefixes(dlink) returned no prefixes")
	}
	for _, prefix := range prefixes {
		if len(prefix) != 6 {
			t.Errorf("OUI prefix %q has wrong length: %d", prefix, len(prefix))
		}
	}
}

func TestVendorCount(t *testing.T) {
	count := VendorCount()
	if count < 10000 {
		t.Errorf("VendorCount() = %d, expected at least 10000 vendors", count)
	}
	t.Logf("VendorCount: %d", count)
}

func TestConcurrentLookup(t *testing.T) {
	done := make(chan bool)
	for index := 0; index < 100; index++ {
		go func() {
			Lookup("00:50:BA:12:34:56")
			Lookup("CC:46:D6:12:34:56")
			Lookup("48:AD:08:12:34:56")
			done <- true
		}()
	}
	for index := 0; index < 100; index++ {
		<-done
	}
}
