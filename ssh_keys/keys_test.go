package ssh_keys

import "testing"

func TestAll(t *testing.T) {
	entries := All()
	if len(entries) < 1 {
		t.Error("Expected at least 1 SSH key entry")
	}
	for _, entry := range entries {
		if entry.Vendor == "" {
			t.Error("KeyEntry has empty Vendor")
		}
		if len(entry.KeyData) == 0 {
			t.Errorf("KeyEntry %s/%s has empty KeyData", entry.Vendor, entry.Model)
		}
	}
}

func TestByVendor(t *testing.T) {
	entries := ByVendor("fortinet")
	if len(entries) == 0 {
		t.Skip("No Fortinet keys found — skipping vendor test")
	}
	if entries[0].Vendor != "fortinet" {
		t.Errorf("Expected vendor 'fortinet', got %q", entries[0].Vendor)
	}
}

func TestByVendor_CaseInsensitive(t *testing.T) {
	entries := ByVendor("FortiNet")
	if len(entries) == 0 {
		t.Skip("No Fortinet keys found")
	}
}

func TestByVendorModel(t *testing.T) {
	entry, err := ByVendorModel("fortinet", "fortigate")
	if err != nil {
		t.Fatalf("ByVendorModel error: %v", err)
	}
	if entry == nil {
		t.Skip("No fortinet/fortigate key found")
	}
	if entry.Username == "" {
		t.Error("KeyEntry has empty Username")
	}
}
