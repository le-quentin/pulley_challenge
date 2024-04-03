package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

const ROOT_URL = "https://ciphersprint.pulley.com/"
const EMAIL = "quentin@bonnet.software"

func main() {
	response := getPath(EMAIL)
	log.Printf("%+v\n", response)
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

func getPath(path string) ChallengeResponse {
	response, err := http.Get(ROOT_URL + EMAIL)
	if err != nil {
		log.Fatal(err)
	}
	if response.StatusCode >= 300 {
		log.Fatal("Call to " + path + " returned status code " + response.Status)
	}

	body, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	responseObject := ChallengeResponse{}
	jsonErr := json.Unmarshal(body, &responseObject)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}

	return responseObject
}
