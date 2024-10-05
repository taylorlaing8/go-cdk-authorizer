package endtoendtest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

type CanaryAuthTokenConfig struct {
	Issuer         string `json:"issuer"`
	ClientId       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	ClientAudience string `json:"client_audience"`
	GrantType      string `json:"grant_type"`
}

type TokenService struct {
	ssManager  *ssm.Client
	authConfig *CanaryAuthTokenConfig
}

var CachedToken *string

func loadTokenService(cfg aws.Config) TokenService {
	tokenService := TokenService{}

	tokenService.ssManager = ssm.NewFromConfig(cfg)

	withDecrypt := true
	ssConfigPath := "/canary/config"
	parameterOutput, _ := tokenService.ssManager.GetParameter(context.TODO(), &ssm.GetParameterInput{Name: &ssConfigPath, WithDecryption: &withDecrypt})

	parameter := *parameterOutput.Parameter.Value

	authConfig := CanaryAuthTokenConfig{}
	json.Unmarshal([]byte(parameter), &authConfig)

	tokenService.authConfig = &authConfig

	return tokenService
}

func (tokenService TokenService) GetAccessToken() string {
	if CachedToken == nil {
		token, _ := acquireToken(tokenService.authConfig)

		CachedToken = token
	}

	return *CachedToken
}

func acquireToken(authConfig *CanaryAuthTokenConfig) (*string, error) {
	reqUrl := authConfig.Issuer + "oauth/token"

	type TokenRequest struct {
		ClientId     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Audience     string `json:"audience"`
		GrantType    string `json:"grant_type"`
	}

	request := &TokenRequest{
		ClientId:     authConfig.ClientId,
		ClientSecret: authConfig.ClientSecret,
		Audience:     authConfig.ClientAudience,
		GrantType:    authConfig.GrantType,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", reqUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := Fixture.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error retrieving authorizer token: %v", resp.StatusCode)
	}

	var respBody struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return nil, fmt.Errorf("error parsing authorizer token: %v", err.Error())
	}

	return &respBody.AccessToken, nil
}
