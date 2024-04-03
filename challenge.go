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
	switch r.Encryption_Method {
		case "nothing" : return r.Encrypted_Path, nil
		default: return "", errors.New("Unkown encryption method: " + r.Encryption_Method)
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
