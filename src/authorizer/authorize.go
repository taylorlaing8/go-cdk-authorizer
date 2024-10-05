package authorize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/golang-jwt/jwt/v5"
)

type AuthTokenConfig struct {
	JwksUri        string `json:"jwks_uri"`
	Issuer         string `json:"issuer"`
	ClientId       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	TokenAudience  string `json:"token_audience"`  // Used to validate incoming token 'aud' claims
	ClientAudience string `json:"client_audience"` // Used to fetch Auth0 token to retrieve roles assigned for incoming token
	GrantType      string `json:"grant_type"`
}

type AuthConfig struct {
	SSManager      *ssm.Client
	SSMConfigPath  string
	Config         *AuthTokenConfig
	JWTKeyFunction keyfunc.Keyfunc
	AuthCache      *AuthCache
}

var Authorizer *AuthConfig

var cachedToken *string

var httpInstance *http.Client

func InitLambda(awsConfig *aws.Config) {
	var cfg aws.Config
	if awsConfig != nil {
		cfg = *awsConfig
	} else {
		loadConfig, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			log.Panicf("Unable to load SDK config, %v", err.Error())
		}
		cfg = loadConfig
	}

	ssConfigPath := os.Getenv("AUTHORIZER_CONFIG_PATH")

	ssMgr := ssm.NewFromConfig(cfg)

	withDecrypt := true
	parameterOutput, _ := ssMgr.GetParameter(context.TODO(), &ssm.GetParameterInput{Name: &ssConfigPath, WithDecryption: &withDecrypt})

	parameter := *parameterOutput.Parameter.Value

	authConfig := AuthTokenConfig{}
	json.Unmarshal([]byte(parameter), &authConfig)

	kFunc, err := keyfunc.NewDefaultCtx(context.Background(), []string{authConfig.JwksUri})
	if err != nil {
		fmt.Printf("Failed to create a keyfunc.Keyfunc from the server's URL.\nError: %s", err)
	}

	httpInstance = &http.Client{Timeout: time.Duration(15) * time.Second}

	// Token expiration set in Auth0 dashboard - currently 24 hours
	acquireToken(&authConfig)

	ddbStore := dynamodb.NewFromConfig(cfg)

	authCache := AuthCache{
		DynamoDb:  ddbStore,
		TableName: os.Getenv("AUTH_CACHE_TABLE_NAME"),
	}

	Authorizer = &AuthConfig{
		SSManager:      ssMgr,
		SSMConfigPath:  ssConfigPath,
		Config:         &authConfig,
		JWTKeyFunction: kFunc,
		AuthCache:      &authCache,
	}
}

func acquireToken(authConfig *AuthTokenConfig) error {
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
		return err
	}

	req, err := http.NewRequest("POST", reqUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := httpInstance.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("error retrieving authorizer token: %v", resp.StatusCode)
	}

	var respBody struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return fmt.Errorf("error parsing authorizer token: %v", err.Error())
	}

	cachedToken = &respBody.AccessToken

	return nil
}

func getToken(event *events.APIGatewayCustomAuthorizerRequest) (string, error) {
	if event.Type != "TOKEN" {
		return "", errors.New("expected 'event.Type' parameter to have value 'TOKEN'")
	}

	tokenString := event.AuthorizationToken
	if len(tokenString) <= 0 {
		return "", errors.New("expected 'event.AuthorizationToken' parameter to not be empty")
	}

	match, _ := regexp.MatchString("Bearer (.*)", tokenString)
	if !match {
		return "", errors.New("invalid authorization token - The provided 'Authorization' header does not match 'Bearer .*'")
	}

	tokenParts := strings.Fields(tokenString)

	return tokenParts[1], nil
}

func Handler(ctx context.Context, req events.APIGatewayCustomAuthorizerRequest) (resp events.APIGatewayCustomAuthorizerResponse, err error) {
	token, err := getToken(&req)
	if err != nil {
		log.Printf("Error retrieving token from request: %v", err.Error())
		return getDenyResponse("", req.MethodArn, "Unauthorized"), nil
	}

	decodedToken, err := jwt.Parse(token, Authorizer.JWTKeyFunction.Keyfunc)

	if err != nil {
		log.Printf("Error decoding token: %v", err.Error())

		switch {
		case errors.Is(err, jwt.ErrTokenMalformed):
			return getDenyResponse("", req.MethodArn, "Unauthorized: Malformed Token"), nil
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return getDenyResponse("", req.MethodArn, "Unauthorized: Invalid Signature"), nil
		case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
			return getDenyResponse("", req.MethodArn, "Unauthorized: Expired Token"), nil
		default:
			return getDenyResponse("", req.MethodArn, "Unauthorized: Unable to decode token"), nil
		}
	}

	var tokenPayload jwt.MapClaims
	if decodedToken != nil {
		tokenPayload = decodedToken.Claims.(jwt.MapClaims)
	}

	if audClaims, err := tokenPayload.GetAudience(); err == nil {
		located := false
		for _, audClaim := range audClaims {
			if audClaim == Authorizer.Config.TokenAudience {
				located = true
			}
		}
		if !located {
			return getDenyResponse("", req.MethodArn, "Unauthorized: Token 'aud' claim missing registered audience"), nil
		}
	} else {
		return getDenyResponse("", req.MethodArn, "Unauthorized: Token missing 'aud' claim or claim is invalid"), nil
	}

	if !decodedToken.Valid {
		return getDenyResponse("", req.MethodArn, "Unauthorized: Token failed validation"), nil
	} else if _, ok := decodedToken.Method.(*jwt.SigningMethodRSA); !ok {
		return getDenyResponse("", req.MethodArn, "Unauthorized: Token uses invalid signing method"), nil
	} else if decodedToken.Header["alg"] == nil {
		return getDenyResponse("", req.MethodArn, "Unauthorized: Token missing required 'alg' claim"), nil
	} else if !strings.Contains(tokenPayload["iss"].(string), Authorizer.Config.Issuer) {
		return getDenyResponse("", req.MethodArn, "Unauthorized: Token uses invalid 'iss' claim"), nil
	}

	lContext := make(map[string]interface{})

	principalId, ok := tokenPayload["sub"].(string)
	if !ok {
		return getDenyResponse("", req.MethodArn, "Unauthorized: Token missing required 'sub' claim"), nil
	}
	lContext["requesterId"] = principalId

	isAppToken := !strings.Contains(principalId, "auth0")

	scopes, ok := tokenPayload["scope"].(string)
	if !ok {
		return getDenyResponse(principalId, req.MethodArn, "Unauthorized: Token missing required 'roles' claim"), nil
	}

	if isAppToken {
		log.Printf("Received token of type: app")

		scopesArray := strings.Split(scopes, " ")
		lContext["permissions"] = strings.Join(scopesArray, ",")
	} else {
		log.Printf("Received token of type: user")

		permissionsChan := make(chan string, 1)
		errChan := make(chan error, 1)

		go func() {
			res, err := getUserPermissions(principalId)
			if err != nil {
				errChan <- err
				return
			}

			permissionsChan <- res
		}()

		select {
		case permissionsArray := <-permissionsChan:
			lContext["permissions"] = permissionsArray
		case err := <-errChan:
			return getDenyResponse(principalId, req.MethodArn, err.Error()), nil
		}
	}

	return getSuccessResponse(principalId, req.MethodArn, &lContext), nil
}

func getUserPermissions(principalId string) (string, error) {
	permissions := ""

	authCache, _ := Authorizer.AuthCache.TryGet(principalId)
	if authCache != nil && authCache.Expiration.After(time.Now()) {
		permissions = strings.Join(authCache.Permissions, ",")
	} else {
		permissionsChan := make(chan []string, 1)
		errChan := make(chan error, 1)

		go func() {
			reqUrl := fmt.Sprintf("%vapi/v2/users/%v/permissions", Authorizer.Config.Issuer, principalId)

			req, err := http.NewRequest("GET", reqUrl, nil)
			if err != nil {
				errChan <- err
				return
			}

			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", *cachedToken))

			resp, err := httpInstance.Do(req)
			if err != nil {
				errChan <- err
				return
			}

			if resp.StatusCode != 200 {
				errChan <- fmt.Errorf("error retrieving user permissions: %v", resp.StatusCode)
				return
			}

			type UserPermission struct {
				PermissionName     string        `json:"permission_name"`
				Description        string        `json:"description"`
				ResourceServerName string        `json:"resource_server_name"`
				ResourceServerId   string        `json:"resource_server_identifier"`
				Sources            []interface{} `json:"sources"`
			}
			var respBody []UserPermission

			err = json.NewDecoder(resp.Body).Decode(&respBody)
			if err != nil {
				errChan <- fmt.Errorf("error parsing user permissions: %v", err.Error())
				return
			}

			permissionsArray := make([]string, 0)
			for _, val := range respBody {
				permissionsArray = append(permissionsArray, val.PermissionName)
			}

			Authorizer.AuthCache.TryPut(principalId, &AuthCacheValue{
				Permissions: permissionsArray,
				Expiration:  time.Now().Add(1000 * 900 * time.Millisecond),
			})

			permissionsChan <- permissionsArray
		}()

		if authCache != nil && authCache.Expiration.After(time.Now()) {
			permissions = strings.Join(authCache.Permissions, ",")
			return permissions, nil
		} else {
			select {
			case permissionsArray := <-permissionsChan:
				permissions = strings.Join(permissionsArray, ",")
			case err := <-errChan:
				return permissions, err
			}
		}
	}

	return permissions, nil
}

func getDenyResponse(principalId string, methodArn string, message string) events.APIGatewayCustomAuthorizerResponse {
	context := make(map[string]interface{})
	context["ErrorMessage"] = message

	policyStatement := events.IAMPolicyStatement{
		Action:   []string{"execute-api:Invoke"},
		Effect:   "Deny",
		Resource: []string{methodArn},
	}

	policyDocument := events.APIGatewayCustomAuthorizerPolicy{
		Version:   "2012-10-17",
		Statement: []events.IAMPolicyStatement{policyStatement},
	}

	authResponse := events.APIGatewayCustomAuthorizerResponse{
		PrincipalID:    principalId,
		PolicyDocument: policyDocument,
		Context:        context,
	}

	return authResponse
}

func getSuccessResponse(principalId string, methodArn string, context *map[string]interface{}) events.APIGatewayCustomAuthorizerResponse {
	policyStatement := events.IAMPolicyStatement{
		Action:   []string{"execute-api:Invoke"},
		Effect:   "Allow",
		Resource: []string{methodArn},
	}

	policyDocument := events.APIGatewayCustomAuthorizerPolicy{
		Version:   "2012-10-17",
		Statement: []events.IAMPolicyStatement{policyStatement},
	}

	authResponse := events.APIGatewayCustomAuthorizerResponse{
		PrincipalID:    principalId,
		PolicyDocument: policyDocument,
		Context:        *context,
	}

	return authResponse
}

func main() {
	lambda.Start(Handler)
}
