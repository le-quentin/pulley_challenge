package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
)

const ROOT_URL = "https://ciphersprint.pulley.com/"
const EMAIL = "quentin@bonnet.software"

func main() {
	nextPath, err := getNextPath(EMAIL)
	if err != nil {
		log.Panic("Error while completing first level: ", err)
	}
	log.Printf("Decrypted next path is: %+v", nextPath)

	nextPath, err = getNextPath(nextPath)
	if err != nil {
		log.Panic("Error while completing second level: ", err)
	}
	log.Printf("Decrypted next path is: %+v", nextPath)

	nextPath, err = getNextPath(nextPath)
	if err != nil {
		log.Panic("Error while completing third level: ", err)
	}
	log.Printf("Decrypted next path is: %+v", nextPath)
}

func getNextPath(path string) (string, error) {
	response, err := getChallengeResposne(path)
	if err != nil {
		return "", err
	}
	log.Printf("Request: %+v, Reply: %+v", path, response)

	nextPath, err := response.Decrypt()
	if err != nil {
		return "", err
	}

	return nextPath, nil
}

type ChallengeResponse struct {
	Challenger        string
	Encrypted_Path    string
	Encryption_Method string
	Expires_In        string
	Hint              string
	Instructions      string
	Level             int32
}

func (r ChallengeResponse) Decrypt() (string, error) {
	if r.Encryption_Method == "nothing" {
		return r.Encrypted_Path, nil
	}

	encrypted := strings.Split(r.Encrypted_Path, "_")[1]
	decrypted, err := decrypt(encrypted, r.Encryption_Method)
	return "task_" + decrypted, err
}

func decrypt(encrypted string, method string) (string, error) {
	switch method {
	case "converted to a JSON array of ASCII values":
		var asciiCodes []byte
		err := json.Unmarshal([]byte(encrypted), &asciiCodes)
		return string(asciiCodes), err
	case "inserted some non-hex characters":
		return regexp.MustCompile(`[^0-9a-fA-F]+`).ReplaceAllString(encrypted, ""), nil
	default:
		return "", errors.New("Unkown encryption method: " + method)
	}
}

func getChallengeResposne(path string) (*ChallengeResponse, error) {
	response, err := http.Get(ROOT_URL + path)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 300 {
		return nil, errors.New("Call to " + path + " returned status code " + response.Status)
	}

	body, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		return nil, readErr
	}

	responseObject := ChallengeResponse{}
	jsonErr := json.Unmarshal(body, &responseObject)
	if jsonErr != nil {
		return nil, jsonErr
	}

	return &responseObject, nil
}

func extractEncryptionMethod(encryptionMethod string) {
}
