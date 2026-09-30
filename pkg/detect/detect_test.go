package detect

import "testing"

func TestVerhoeff(t *testing.T) {
	// 236 -> check digit 3 is the textbook example.
	if got := VerhoeffCheckDigit("236"); got != '3' {
		t.Fatalf("VerhoeffCheckDigit(236) = %c, want 3", got)
	}
	if !VerhoeffValid("2363") {
		t.Error("2363 should be Verhoeff-valid")
	}
	if VerhoeffValid("2364") || VerhoeffValid("") || VerhoeffValid("23a3") {
		t.Error("invalid inputs accepted")
	}
	// Every single-digit error must be caught.
	base := "23456789012"
	valid := base + string(VerhoeffCheckDigit(base))
	for i := range valid {
		for d := byte('0'); d <= '9'; d++ {
			if d == valid[i] {
				continue
			}
			mutated := valid[:i] + string(d) + valid[i+1:]
			if VerhoeffValid(mutated) {
				t.Fatalf("single-digit error %s -> %s not detected", valid, mutated)
			}
		}
	}
	// ...and every adjacent transposition.
	for i := 0; i+1 < len(valid); i++ {
		if valid[i] == valid[i+1] {
			continue
		}
		b := []byte(valid)
		b[i], b[i+1] = b[i+1], b[i]
		if VerhoeffValid(string(b)) {
			t.Fatalf("transposition %s -> %s not detected", valid, b)
		}
	}
}

func TestIsAadhaar(t *testing.T) {
	base := "23456789012"
	valid := base + string(VerhoeffCheckDigit(base))
	cases := []struct {
		in   string
		want bool
	}{
		{valid, true},
		{valid[:4] + " " + valid[4:8] + " " + valid[8:], true},
		{valid[:4] + "-" + valid[4:8] + "-" + valid[8:], true},
		{"1" + valid[1:], false}, // Aadhaar numbers never start with 0 or 1
		{valid[:11], false},      // too short
		{valid[:11] + "0", valid[11] == '0'},
	}
	for _, c := range cases {
		if got := IsAadhaar(c.in); got != c.want {
			t.Errorf("IsAadhaar(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPaymentCards(t *testing.T) {
	cards := map[string]bool{
		"4111111111111111":    true,  // Visa test number
		"4111 1111 1111 1111": true,  // with separators
		"5500005555555559":    true,  // Mastercard
		"2223000048400011":    true,  // Mastercard 2-series
		"378282246310005":     true,  // American Express
		"6011111111111117":    true,  // Discover
		"4111111111111112":    false, // Luhn failure
		"1234567812345670":    false, // Luhn-valid, but no issuer uses prefix 1
		"411111111111":        false, // too short
	}
	for in, want := range cards {
		if got := IsPaymentCard(in); got != want {
			t.Errorf("IsPaymentCard(%q) = %v, want %v", in, got, want)
		}
	}
	if !LuhnValid("1234567812345670") {
		t.Error("1234567812345670 is Luhn-valid")
	}
	if LuhnValid("7") || LuhnValid("12a4") {
		t.Error("LuhnValid accepted invalid input")
	}
}

func TestMasking(t *testing.T) {
	cases := []struct{ got, want string }{
		{MaskTail("1234 5678 9012", 4), "**** **** 9012"},
		{MaskTail("ABCDE1234F", 2), "********4F"},
		{MaskSecret("supersecretpassword1"), "su***(20 chars)"},
		{MaskSecret("abc123"), "******"},
		{MaskSecret(""), ""},
		{MaskEmail("komal@example.com"), "k***@example.com"},
		{MaskEmail("not-an-email"), "no***(12 chars)"},
		{Digits("+91 98765-43210"), "919876543210"},
	}
	for i, c := range cases {
		if c.got != c.want {
			t.Errorf("case %d: got %q, want %q", i, c.got, c.want)
		}
	}
}
