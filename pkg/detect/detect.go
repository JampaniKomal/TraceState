// Package detect holds the validation algorithms and redaction helpers the
// scanner wires use to keep false positives down and keep sensitive values
// out of reports and the ledger.
package detect

import (
	"strings"
)

// Verhoeff tables (dihedral group D5), used by the Aadhaar check digit.
var (
	verhoeffD = [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	verhoeffP = [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
	verhoeffInv = [10]byte{0, 4, 3, 2, 1, 5, 9, 8, 7, 6}
)

// Digits strips everything except ASCII digits.
func Digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// VerhoeffValid reports whether the digit string carries a valid Verhoeff
// check digit in its last position.
func VerhoeffValid(digits string) bool {
	if digits == "" {
		return false
	}
	c := 0
	for i := 0; i < len(digits); i++ {
		d := digits[len(digits)-1-i]
		if d < '0' || d > '9' {
			return false
		}
		c = verhoeffD[c][verhoeffP[i%8][d-'0']]
	}
	return c == 0
}

// VerhoeffCheckDigit returns the digit that makes digits+check Verhoeff-valid.
func VerhoeffCheckDigit(digits string) byte {
	c := 0
	for i := 0; i < len(digits); i++ {
		d := digits[len(digits)-1-i]
		c = verhoeffD[c][verhoeffP[(i+1)%8][d-'0']]
	}
	return '0' + verhoeffInv[c]
}

// IsAadhaar reports whether s is a structurally valid Aadhaar number: twelve
// digits, not starting with 0 or 1, with a valid Verhoeff check digit.
func IsAadhaar(s string) bool {
	d := Digits(s)
	return len(d) == 12 && d[0] >= '2' && VerhoeffValid(d)
}

// LuhnValid reports whether the digit string passes the Luhn (mod 10) check.
func LuhnValid(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// IsPaymentCard reports whether s looks like a real card number: 13 to 19
// digits, a known issuer prefix, and a valid Luhn checksum.
func IsPaymentCard(s string) bool {
	d := Digits(s)
	if len(d) < 13 || len(d) > 19 || !LuhnValid(d) {
		return false
	}
	return knownIssuer(d)
}

func knownIssuer(d string) bool {
	prefix := func(n int) int {
		v := 0
		for i := 0; i < n && i < len(d); i++ {
			v = v*10 + int(d[i]-'0')
		}
		return v
	}
	p1, p2, p3, p4 := prefix(1), prefix(2), prefix(3), prefix(4)
	switch {
	case p1 == 4: // Visa
		return true
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720: // Mastercard
		return true
	case p2 == 34 || p2 == 37: // American Express
		return true
	case p4 == 6011 || p2 == 65 || (p3 >= 644 && p3 <= 649): // Discover
		return true
	case p2 == 35: // JCB
		return true
	case p2 == 60 || p2 == 81 || p2 == 82 || p3 == 508 || p3 == 353 || p3 == 356: // RuPay
		return true
	case p2 == 36 || p2 == 38 || p2 == 39 || (p3 >= 300 && p3 <= 305): // Diners Club
		return true
	}
	return false
}

// MaskTail keeps the last `keep` characters of s and replaces every other
// letter or digit with '*', preserving separators so the shape stays readable.
func MaskTail(s string, keep int) string {
	runes := []rune(s)
	kept := 0
	for i := len(runes) - 1; i >= 0; i-- {
		r := runes[i]
		if !isAlnum(r) {
			continue
		}
		if kept < keep {
			kept++
			continue
		}
		runes[i] = '*'
	}
	return string(runes)
}

// MaskSecret shows at most the first two characters of a secret followed by
// its length, e.g. "su***(20 chars)". Short values are fully masked.
func MaskSecret(s string) string {
	n := len([]rune(s))
	if n <= 6 {
		return strings.Repeat("*", n)
	}
	return string([]rune(s)[:2]) + "***(" + itoa(n) + " chars)"
}

// MaskEmail keeps the first character of the local part and the domain.
func MaskEmail(s string) string {
	at := strings.LastIndexByte(s, '@')
	if at <= 0 {
		return MaskSecret(s)
	}
	return s[:1] + "***" + s[at:]
}

func isAlnum(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
