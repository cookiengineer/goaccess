package ssh_keys

import (
	"embed"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed generic/*/*.key generic/*/*.json
//go:embed f5/*/*.key f5/*/*.json
//go:embed barracuda/*/*.key barracuda/*/*.json
//go:embed exagrid/*/*.key exagrid/*/*.json
//go:embed quantum/*/*.key quantum/*/*.json
//go:embed array_networks/*/*.key array_networks/*/*.json
//go:embed ceragon/*/*.key ceragon/*/*.json
//go:embed monroe/*/*.key monroe/*/*.json
//go:embed loadbalancer/*/*.key loadbalancer/*/*.json
var KeyFiles embed.FS

// KeyEntry represents a known hardcoded SSH key pair.
type KeyEntry struct {
	Vendor   string
	Model    string
	Username string
	KeyData  []byte
	Type     string
	Comment  string
}

type keyMetadata struct {
	Username string `json:"username"`
	Type     string `json:"type"`
	Comment  string `json:"comment"`
}

var (
	once       sync.Once
	keyEntries []KeyEntry
)

func init() {
	ensureLoaded()
}

func ensureLoaded() {
	once.Do(loadKeys)
}

func loadKeys() {
	entries, err := KeyFiles.ReadDir(".")
	if err != nil {
		return
	}

	for _, vendorEntry := range entries {
		if !vendorEntry.IsDir() {
			continue
		}

		modelEntries, err := KeyFiles.ReadDir(vendorEntry.Name())
		if err != nil {
			continue
		}

		for _, modelEntry := range modelEntries {
			if !modelEntry.IsDir() {
				continue
			}

			dirPath := vendorEntry.Name() + "/" + modelEntry.Name()

			var keyData []byte
			var metadata keyMetadata

			files, err := KeyFiles.ReadDir(dirPath)
			if err != nil {
				continue
			}

			for _, file := range files {
				if strings.HasSuffix(file.Name(), ".key") {
					keyData, _ = KeyFiles.ReadFile(filepath.Join(dirPath, file.Name()))
				}
				if strings.HasSuffix(file.Name(), ".json") {
					jsonData, err := KeyFiles.ReadFile(filepath.Join(dirPath, file.Name()))
					if err == nil {
						json.Unmarshal(jsonData, &metadata)
					}
				}
			}

			if len(keyData) > 0 {
				keyEntries = append(keyEntries, KeyEntry{
					Vendor:   vendorEntry.Name(),
					Model:    modelEntry.Name(),
					Username: metadata.Username,
					KeyData:  keyData,
					Type:     metadata.Type,
					Comment:  metadata.Comment,
				})
			}
		}
	}
}

// All returns every registered SSH key entry.
func All() []KeyEntry {
	ensureLoaded()
	result := make([]KeyEntry, len(keyEntries))
	copy(result, keyEntries)
	return result
}

// ByVendor returns SSH keys for a specific vendor.
func ByVendor(vendor string) []KeyEntry {
	ensureLoaded()
	var matches []KeyEntry
	for _, entry := range keyEntries {
		if matchesVendor(entry.Vendor, vendor) {
			matches = append(matches, entry)
		}
	}
	return matches
}

// ByVendorModel returns the SSH key for a specific vendor and model.
func ByVendorModel(vendor, model string) (*KeyEntry, error) {
	ensureLoaded()
	for _, entry := range keyEntries {
		if matchesVendor(entry.Vendor, vendor) && entry.Model == model {
			return &entry, nil
		}
	}
	return nil, nil
}

func matchesVendor(actual, target string) bool {
	if len(actual) < len(target) {
		return false
	}
	return strings.EqualFold(actual[:len(target)], target)
}
