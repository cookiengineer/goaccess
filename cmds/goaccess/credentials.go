package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// loadPasswordList reads a password list file (one password per line), e.g.
// rockyou.txt. Blank lines and # comments are ignored.
func loadPasswordList(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open password list: %w", err)
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		passwords = append(passwords, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading password list: %w", err)
	}
	return passwords, nil
}
