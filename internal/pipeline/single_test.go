package pipeline

import "testing"

func TestNormalizeVerificationCode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "abc-123\n", want: "ABC-123"},
		{in: "a1b2c3", want: "A1B2C3"},
	}
	for _, tt := range tests {
		got, err := normalizeVerificationCode(tt.in)
		if err != nil {
			t.Fatalf("normalizeVerificationCode(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("normalizeVerificationCode(%q)=%q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeVerificationCodeRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"", "ABC12", "ABC--123", "ABC_123", "ABCD-123", "A-BC123"} {
		if _, err := normalizeVerificationCode(input); err == nil {
			t.Fatalf("normalizeVerificationCode(%q) unexpectedly succeeded", input)
		}
	}
}

func TestSingleAccountPasswordHasRequiredClasses(t *testing.T) {
	password, err := singleAccountPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 18 {
		t.Fatalf("password length=%d", len(password))
	}
	if password[0] != 'G' || password[1] != 'r' || password[2] != '7' {
		t.Fatalf("password does not preserve required classes")
	}
}
