package payload

import (
	"fmt"
	"os"
)

// Arch represents a target CPU architecture.
type Arch string

const (
	ARM    Arch = "arm"
	ARM64  Arch = "arm64"
	MIPS   Arch = "mips"
	MIPSLE Arch = "mipsle"
	MIPS64 Arch = "mips64"
	X86    Arch = "x86"
	X86_64 Arch = "x86_64"
)

// Handler represents a shell connection type.
type Handler string

const (
	ReverseTCP Handler = "reverse_tcp"
	BindTCP    Handler = "bind_tcp"
)

// PayloadInfo describes an available pre-compiled payload.
type PayloadInfo struct {
	Arch    Arch
	Handler Handler
	Size    int64
	Path    string
}

// basePath is the directory containing pre-built payload binaries.
// This is resolved relative to the working directory.
var basePath = "payload"

// SetBasePath overrides the default payload directory.
func SetBasePath(path string) {
	basePath = path
}

// GetPayload reads the pre-compiled payload binary for the given architecture and handler.
// Run `make payloads` first to build the binaries.
func GetPayload(arch Arch, handler Handler) ([]byte, error) {
	filename := fmt.Sprintf("%s/%s/%s", basePath, arch, handler)
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("payload: %s not found (run 'make payloads' to build): %w", filename, err)
	}
	return data, nil
}

// List returns all available (architecture, handler) combinations
// by scanning the payload directory.
func List() []PayloadInfo {
	var info []PayloadInfo

	archDirs, err := os.ReadDir(basePath)
	if err != nil {
		return nil
	}

	for _, archEntry := range archDirs {
		if !archEntry.IsDir() {
			continue
		}
		arch := Arch(archEntry.Name())
		archPath := basePath + "/" + string(arch)

		handlerFiles, err := os.ReadDir(archPath)
		if err != nil {
			continue
		}

		for _, handlerFile := range handlerFiles {
			if handlerFile.IsDir() {
				continue
			}
			fileInfo, _ := handlerFile.Info()
			size := int64(0)
			if fileInfo != nil {
				size = fileInfo.Size()
			}

			info = append(info, PayloadInfo{
				Arch:    arch,
				Handler: Handler(handlerFile.Name()),
				Size:    size,
				Path:    fmt.Sprintf("%s/%s", archPath, handlerFile.Name()),
			})
		}
	}

	return info
}
