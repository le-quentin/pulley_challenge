package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
)

const ROOT_URL = "https://ciphersprint.pulley.com/"
const EMAIL = "quentin@bonnet.software"

func main() {
	response, err := getPath(EMAIL)
	if err != nil {
		log.Panic("Error while completing first level: ", err)
	}
	log.Printf("%+v", response)
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

func getPath(path string) (*ChallengeResponse, error) {
	response, err := http.Get(ROOT_URL + EMAIL)
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
