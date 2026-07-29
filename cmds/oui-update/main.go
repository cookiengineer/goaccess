package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	ouiURL     = "https://standards-oui.ieee.org/"
	outputPath = "oui/oui.dat"
)

var headerPattern = regexp.MustCompile(`^[A-F0-9]{6}\s+\(base 16\)\s+(.+)`)
var hexOnly = regexp.MustCompile(`^[A-F0-9a-f]{6}$`)

var companyForms = []string{
	"ab",
	"a/b",
	"ag",
	"aps",
	"as",
	"a/s",
	"bhd",
	"bv",
	"coltd",
	"co ltd",
	"company",
	"corp",
	"corporation",
	"gmbh & co kg",
	"gmbh",
	"inc",
	"incorporated",
	"intl",
	"int'l",
	"international",
	"kb",
	"kft",
	"kk",
	"k k",
	"limited",
	"llc",
	"ltd",
	"lp",
	"llp",
	"nv",
	"oy",
	"oyj",
	"plc",
	"pte",
	"pty",
	"sa",
	"sas",
	"sarl",
	"sdn",
	"sl",
	"spa",
	"srl",
	"technologies co",
	"technology co",
	"t & m",
}

var companySuffixes = []string{
	"co",
	"mbh",
}

func init() {

	sort.Slice(companyForms, func(i, j int) bool {

		li, lj := len(companyForms[i]), len(companyForms[j])

		// Longer strings come first.
		if li != lj {
			return li > lj
		}

		// Same length: sort alphabetically.
		return companyForms[i] < companyForms[j]

	})

}

func main() {
	request, err := http.NewRequest("GET", ouiURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %s\n", err)
		os.Exit(1)
	}
	request.Header.Set("User-Agent", "GoAccess OUI Updater/1.0")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading OUI data: %s\n", err)
		os.Exit(1)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "HTTP %d from OUI server\n", response.StatusCode)
		os.Exit(1)
	}

	entries, err := parseOUI(response.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing OUI data: %s\n", err)
		os.Exit(1)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating %s: %s\n", outputPath, err)
		os.Exit(1)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, entry := range entries {
		writer.WriteString(entry + "\n")
	}
	writer.Flush()

	fmt.Printf("OUI database updated: %d entries written to %s\n", len(entries), outputPath)
}

func parseOUI(reader io.Reader) ([]string, error) {
	var entries []string
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()

		matches := headerPattern.FindStringSubmatch(line)
		if len(matches) != 2 {
			continue
		}

		oui := strings.ToUpper(strings.TrimSpace(line[:6]))
		if !hexOnly.MatchString(oui) {
			continue
		}

		vendor := strings.TrimSpace(matches[1])
		if vendor == "" {
			continue
		}

		vendor = sanitizeVendor(vendor)
		if vendor == "" {
			continue
		}

		entries = append(entries, oui+" "+vendor)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	sort.Strings(entries)
	return entries, nil
}

func sanitizeVendor(name string) string {

	if strings.Contains(name, "(") {
		name = strings.TrimSpace(name[0:strings.Index(name, "(")])
	}

	if strings.Contains(name, "[") {
		name = strings.TrimSpace(name[0:strings.Index(name, "[")])
	}

	if strings.Contains(name, "{") {
		name = strings.TrimSpace(name[0:strings.Index(name, "{")])
	}

	if strings.Contains(name, ",") {
		name = strings.TrimSpace(name[0:strings.Index(name, ",")])
	}

	name = strings.ReplaceAll(name, "`", "'")
	name = strings.ReplaceAll(name, ".", "")
	name = strings.ReplaceAll(name, "-", "")

	words := strings.Fields(name)
	name = strings.Join(words, " ")

	for _, form := range companyForms {

		tmp := strings.ToLower(name)
		index := strings.Index(tmp, fmt.Sprintf(" %s", form))

		if index != -1 {
			name = strings.TrimSpace(name[0:index])
		}

	}

	for _, suffix := range companySuffixes {

		tmp := strings.ToLower(name)

		if strings.HasSuffix(tmp, fmt.Sprintf(" %s", suffix)) {
			name = name[0:len(name) - len(suffix) - 1]
			break
		}

	}

	name = strings.ReplaceAll(name, " & ", " and ")

	return strings.TrimSpace(name)

}
