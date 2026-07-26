package main

import (
	"context"
	"strings"
	"testing"
)

func TestParseTestEmailArgs(t *testing.T) {
	for _, args := range [][]string{
		{"--email", "person@outlook.com"},
		{"-e", "person@outlook.com"},
		{"--email=person@outlook.com"},
	} {
		got, err := parseTestEmailArgs(args)
		if err != nil {
			t.Fatalf("parseTestEmailArgs(%v): %v", args, err)
		}
		if got.Email != "person@outlook.com" {
			t.Fatalf("email=%q", got.Email)
		}
	}
}

func TestParseTestEmailArgsRejectsMissingOrDuplicate(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--email"},
		{"--email", "a@b.com", "--email", "c@d.com"},
		{"a@b.com"},
	} {
		if _, err := parseTestEmailArgs(args); err == nil {
			t.Fatalf("parseTestEmailArgs(%v) unexpectedly succeeded", args)
		}
	}
}

func TestValidateTestEmail(t *testing.T) {
	if err := validateTestEmail("person@outlook.com"); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", "not-an-email", "Name <person@outlook.com>", "a@b.com\nBCC:x@y.com"} {
		if err := validateTestEmail(input); err == nil {
			t.Fatalf("validateTestEmail(%q) unexpectedly succeeded", input)
		}
	}
}

func TestTerminalCodeReader(t *testing.T) {
	var out strings.Builder
	read := terminalCodeReader(strings.NewReader("abc-123\n"), &out)
	got, err := read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc-123" {
		t.Fatalf("code=%q", got)
	}
	if !strings.Contains(out.String(), "验证码") {
		t.Fatalf("prompt missing: %q", out.String())
	}
}
