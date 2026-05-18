package pii

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"unicode"
)

func validIPv4(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() != nil
}

func validIPv6(value string) bool {
	ip := net.ParseIP(value)
	return strings.Contains(value, ":") && ip != nil
}

func validLuhn(value string) bool {
	digits := onlyDigits(value)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for index := len(digits) - 1; index >= 0; index-- {
		digit := int(digits[index] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

func validIBAN(value string) bool {
	normalized := normalizeIBAN(value)
	if len(normalized) < 15 || len(normalized) > 34 {
		return false
	}
	if !isUpperLetter(normalized[0]) || !isUpperLetter(normalized[1]) || !isDigit(normalized[2]) || !isDigit(normalized[3]) {
		return false
	}
	rearranged := normalized[4:] + normalized[:4]
	remainder := 0
	for _, char := range rearranged {
		switch {
		case char >= '0' && char <= '9':
			remainder = (remainder*10 + int(char-'0')) % 97
		case char >= 'A' && char <= 'Z':
			value := int(char-'A') + 10
			remainder = (remainder*100 + value) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

func validJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for index, part := range parts {
		if part == "" {
			return false
		}
		decoded, err := decodeBase64URL(part)
		if err != nil {
			return false
		}
		if index < 2 && !json.Valid(decoded) {
			return false
		}
	}
	return true
}

func validNLBSN(value string) bool {
	digits := onlyDigits(value)
	if len(digits) == 8 {
		digits = "0" + digits
	}
	if len(digits) != 9 {
		return false
	}
	sum := 0
	for index := 0; index < 8; index++ {
		sum += int(digits[index]-'0') * (9 - index)
	}
	sum -= int(digits[8] - '0')
	return sum%11 == 0
}

func validFRNIR(value string) bool {
	digits := onlyDigits(value)
	if len(digits) != 15 {
		return false
	}
	body := digits[:13]
	keyValue, err := strconv.Atoi(digits[13:])
	if err != nil {
		return false
	}
	remainder := 0
	for _, char := range body {
		remainder = (remainder*10 + int(char-'0')) % 97
	}
	expected := 97 - remainder
	if expected == 97 {
		expected = 0
	}
	return expected == keyValue
}

func validESDNI(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if len(normalized) != 9 {
		return false
	}
	if !isDigitString(normalized[:8]) || !isUpperLetter(normalized[8]) {
		return false
	}
	number, err := strconv.Atoi(normalized[:8])
	if err != nil {
		return false
	}
	return dniLetter(number) == normalized[8]
}

func validESNIE(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if len(normalized) != 9 {
		return false
	}
	prefixes := map[byte]byte{'X': '0', 'Y': '1', 'Z': '2'}
	prefix, ok := prefixes[normalized[0]]
	if !ok || !isDigitString(normalized[1:8]) || !isUpperLetter(normalized[8]) {
		return false
	}
	number, err := strconv.Atoi(string(prefix) + normalized[1:8])
	if err != nil {
		return false
	}
	return dniLetter(number) == normalized[8]
}

func validITCodiceFiscale(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if len(normalized) != 16 {
		return false
	}
	for _, char := range normalized {
		if !unicode.IsDigit(char) && (char < 'A' || char > 'Z') {
			return false
		}
	}
	sum := 0
	for index := 0; index < 15; index++ {
		char := normalized[index]
		if index%2 == 0 {
			sum += codiceFiscaleOddValue(char)
		} else {
			sum += codiceFiscaleEvenValue(char)
		}
	}
	expected := byte('A' + (sum % 26))
	return expected == normalized[15]
}

func validPLPESEL(value string) bool {
	digits := onlyDigits(value)
	if len(digits) != 11 {
		return false
	}
	weights := []int{1, 3, 7, 9, 1, 3, 7, 9, 1, 3}
	sum := 0
	for index, weight := range weights {
		sum += int(digits[index]-'0') * weight
	}
	expected := (10 - (sum % 10)) % 10
	return expected == int(digits[10]-'0')
}

func normalizeIBAN(value string) string {
	var builder strings.Builder
	for _, char := range value {
		if unicode.IsSpace(char) {
			continue
		}
		builder.WriteRune(unicode.ToUpper(char))
	}
	return builder.String()
}

func onlyDigits(value string) string {
	var builder strings.Builder
	for _, char := range value {
		if unicode.IsDigit(char) {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

func isDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func isUpperLetter(value byte) bool {
	return value >= 'A' && value <= 'Z'
}

func isDigitString(value string) bool {
	for index := 0; index < len(value); index++ {
		if !isDigit(value[index]) {
			return false
		}
	}
	return true
}

func dniLetter(number int) byte {
	const letters = "TRWAGMYFPDXBNJZSQVHLCKE"
	return letters[number%23]
}

func decodeBase64URL(value string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	padding := len(value) % 4
	if padding != 0 {
		value += strings.Repeat("=", 4-padding)
	}
	return base64.URLEncoding.DecodeString(value)
}

func codiceFiscaleEvenValue(char byte) int {
	if char >= '0' && char <= '9' {
		return int(char - '0')
	}
	return int(char - 'A')
}

func codiceFiscaleOddValue(char byte) int {
	values := map[byte]int{
		'0': 1, '1': 0, '2': 5, '3': 7, '4': 9, '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
		'A': 1, 'B': 0, 'C': 5, 'D': 7, 'E': 9, 'F': 13, 'G': 15, 'H': 17, 'I': 19, 'J': 21,
		'K': 2, 'L': 4, 'M': 18, 'N': 20, 'O': 11, 'P': 3, 'Q': 6, 'R': 8, 'S': 12, 'T': 14,
		'U': 16, 'V': 10, 'W': 22, 'X': 25, 'Y': 24, 'Z': 23,
	}
	return values[char]
}
