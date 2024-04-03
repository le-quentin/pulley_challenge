package decrypt

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

func FromMethod(encrypted string, method string) (string, error) {
	if method == "converted to a JSON array of ASCII values" {
		var asciiCodes []byte
		err := json.Unmarshal([]byte(encrypted), &asciiCodes)
		return string(asciiCodes), err
	}

	if method == "inserted some non-hex characters" {
		return regexp.MustCompile(`[^0-9a-fA-F]+`).ReplaceAllString(encrypted, ""), nil
	}

	if strings.Contains(method, "circularly rotated left") {
		charsToRotate, err := strconv.Atoi(method[strings.LastIndex(method, " ")+1:])
		if err != nil {
			return "", err
		}
		return rotateRightBy(encrypted, charsToRotate), nil
	}

	if method == "hex decoded, encrypted with XOR, hex encoded again. key: secret" {
		hexDecoded, err := hex.DecodeString(encrypted)
		if err != nil {
			return "", err
		}
		xorDecrypted := xorWithStringKey([]byte(hexDecoded), "secret")
		return hex.EncodeToString(xorDecrypted), nil
	}

	if strings.Contains(method, "scrambled! original positions as base64 encoded messagepack") {
		return Scrambled(encrypted, method[strings.LastIndex(method, " ")+1:])
	}

	return "", errors.New("Unkown encryption method: " + method)
}

func xorWithStringKey(input []byte, key string) []byte {
	kL := len(key)

	var result []byte
	for i := 0; i < len(input); i++ {
		result = append(result, input[i]^key[i%kL])
	}
	return result
}

func rotateRightBy(str string, n int) string {
	charsCount := len(str)
	shift := n % charsCount
	if shift == 0 {
		return str
	}
	return str[charsCount-shift:] + str[0:charsCount-shift]
}
