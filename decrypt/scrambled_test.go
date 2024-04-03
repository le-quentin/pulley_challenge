package decrypt

import (
	"testing"
)

func TestScrambled(t *testing.T) {
	decrypted, err := Scrambled("13758bedd318ca614e632e258ba3fe78", "3AAgHRofEQkIBhUQBRgZAxsEDRQXDgoWARwTDBICCwceAA8=")
	if err != nil {
		t.Error(err)
	}

	if decrypted != "7eac63efb8338168d5b54d2e183a21e7" {
		t.Fatalf("Expected 7eac63efb8338168d5b54d2e183a21e7 but got %s", decrypted)
	}
}
