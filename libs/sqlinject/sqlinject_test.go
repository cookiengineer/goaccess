package sqlinject

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// mockMySQL emulates a MySQL backend vulnerable to error-based SQLi.
func mockMySQL(payload string) (Response, error) {
	if strings.Contains(payload, "'") || strings.Contains(payload, "CONVERT") {
		return Response{StatusCode: 200, Body: []byte("You have an error in your SQL syntax")}, nil
	}
	return Response{StatusCode: 200, Body: []byte("ok")}, nil
}

// mockNonVulnerable returns identical responses regardless of payload.
func mockNonVulnerable(payload string) (Response, error) {
	return Response{StatusCode: 200, Body: []byte("ok")}, nil
}

func TestDetect_ErrorBased_MySQL(t *testing.T) {
	detection, err := Detect(mockMySQL)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if !detection.Vulnerable {
		t.Fatal("expected vulnerable")
	}
	if detection.Technique != TechniqueError {
		t.Errorf("technique = %q, want %q", detection.Technique, TechniqueError)
	}
	if detection.Database != DatabaseMySQL {
		t.Errorf("database = %q, want %q", detection.Database, DatabaseMySQL)
	}
}

func TestDetect_NotVulnerable(t *testing.T) {
	detection, err := Detect(mockNonVulnerable)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if detection.Vulnerable {
		t.Fatal("expected not vulnerable")
	}
}

func TestDetect_BooleanBlind(t *testing.T) {
	request := func(payload string) (Response, error) {
		if strings.Contains(payload, "1=1") {
			return Response{StatusCode: 200, Body: []byte("record found")}, nil
		}
		return Response{StatusCode: 200, Body: []byte("no records")}, nil
	}
	detection, err := Detect(request)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if !detection.Vulnerable {
		t.Fatal("expected vulnerable (boolean-based)")
	}
	if detection.Technique != TechniqueBoolean {
		t.Errorf("technique = %q, want %q", detection.Technique, TechniqueBoolean)
	}
}

func TestDetect_TimeBased(t *testing.T) {
	request := func(payload string) (Response, error) {
		if strings.Contains(payload, "SLEEP") {
			time.Sleep(3100 * time.Millisecond)
		}
		return Response{StatusCode: 200, Body: []byte("ok")}, nil
	}
	detection, err := Detect(request)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if !detection.Vulnerable {
		t.Fatal("expected vulnerable (time-based)")
	}
	if detection.Technique != TechniqueTime {
		t.Errorf("technique = %q, want %q", detection.Technique, TechniqueTime)
	}
	if detection.Database != DatabaseMySQL {
		t.Errorf("database = %q, want %q", detection.Database, DatabaseMySQL)
	}
}

func TestFingerprint_MSSQL(t *testing.T) {
	request := func(payload string) (Response, error) {
		if strings.Contains(payload, "'") {
			return Response{StatusCode: 500, Body: []byte("Unclosed quotation mark after the character string")}, nil
		}
		return Response{StatusCode: 200, Body: []byte("ok")}, nil
	}
	if db := Fingerprint(request); db != DatabaseMSSQL {
		t.Errorf("Fingerprint() = %q, want %q", db, DatabaseMSSQL)
	}
}

func TestFingerprint_Unknown(t *testing.T) {
	if db := Fingerprint(mockNonVulnerable); db != DatabaseUnknown {
		t.Errorf("Fingerprint() = %q, want %q", db, DatabaseUnknown)
	}
}

func TestColumnCount(t *testing.T) {
	// 3-column table: ORDER BY 1..3 succeed, ORDER BY 4 errors.
	request := func(payload string) (Response, error) {
		for column := 1; column <= 3; column++ {
			if strings.Contains(payload, fmt.Sprintf("ORDER BY %d", column)) {
				return Response{StatusCode: 200, Body: []byte("ok")}, nil
			}
		}
		return Response{StatusCode: 500, Body: []byte("Unknown column")}, nil
	}
	count, err := ColumnCount(request, 8)
	if err != nil {
		t.Fatalf("ColumnCount() error: %v", err)
	}
	if count != 3 {
		t.Errorf("ColumnCount() = %d, want 3", count)
	}
}

func TestConcatExpr_MySQL(t *testing.T) {
	expr := ConcatExpr(DatabaseMySQL, []string{"user_login", "user_pass"})
	if !strings.Contains(expr, "CONCAT_WS") || !strings.Contains(expr, "user_login") {
		t.Errorf("ConcatExpr(mysql) = %q", expr)
	}
}

func TestConcatExpr_MSSQL(t *testing.T) {
	expr := ConcatExpr(DatabaseMSSQL, []string{"a", "b"})
	if !strings.Contains(expr, "CONVERT") || !strings.Contains(expr, "+") {
		t.Errorf("ConcatExpr(mssql) = %q", expr)
	}
}

func TestUnionExtract(t *testing.T) {
	// 2-column table, extraction succeeds on output column 2.
	request := func(payload string) (Response, error) {
		if strings.Contains(payload, "NULL,") && strings.Contains(payload, "CONCAT_WS") {
			return Response{StatusCode: 200, Body: []byte(UnionSeparator + "admin" + UnionSeparator + "hash123" + UnionSeparator)}, nil
		}
		return Response{StatusCode: 200, Body: []byte("ok")}, nil
	}
	rows, err := UnionExtract(request, 2, ConcatExpr(DatabaseMySQL, []string{"user_login", "user_pass"}))
	if err != nil {
		t.Fatalf("UnionExtract() error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0][0] != "admin" || rows[0][1] != "hash123" {
		t.Errorf("row = %v, want [admin hash123]", rows[0])
	}
}

func TestQuoteIdentifier(t *testing.T) {
	if got := QuoteIdentifier(DatabaseMySQL, "users"); got != "`users`" {
		t.Errorf("mysql quote = %q, want `users`", got)
	}
	if got := QuoteIdentifier(DatabaseMSSQL, "users"); got != "[users]" {
		t.Errorf("mssql quote = %q, want [users]", got)
	}
}

func TestIntegers(t *testing.T) {
	got := Integers([]string{"3", "1", "x", "2"})
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Errorf("Integers() = %v, want [1 2 3]", got)
	}
}

func TestDetection_String(t *testing.T) {
	d := Detection{Vulnerable: true, Technique: TechniqueError, Database: DatabaseMySQL}
	if d.String() != "error-based (mysql)" {
		t.Errorf("String() = %q", d.String())
	}
	d2 := Detection{}
	if d2.String() != "not vulnerable" {
		t.Errorf("String() = %q", d2.String())
	}
}
