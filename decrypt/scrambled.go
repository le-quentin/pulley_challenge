package decrypt

import (
	"encoding/base64"

	"github.com/vmihailenco/msgpack/v5"
)

func Scrambled(encrypted string, encodedPositions string) (string, error) {
	messagePackPositions, err := base64.StdEncoding.DecodeString(encodedPositions)
	if err != nil {
		return "", err
	}

	var positions []int
	if err := msgpack.Unmarshal(messagePackPositions, &positions); err != nil {
		return "", err
	}

	result := make([]rune, len(encrypted))
	for i, char := range encrypted {
		result[positions[i]] = char
	}

	return string(result), nil
}
