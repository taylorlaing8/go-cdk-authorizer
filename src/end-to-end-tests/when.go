package endtoendtest

import (
	"context"

	auth "cf-authorizer/authorizer"

	"github.com/aws/aws-lambda-go/events"
	"github.com/google/uuid"
)

// Authorizer
func WhenWeSendAuthorizationToken(token string) (resp *events.APIGatewayCustomAuthorizerResponse, err error) {
	authRequest := &events.APIGatewayCustomAuthorizerRequest{
		Type:               "TOKEN",
		AuthorizationToken: token,
		MethodArn:          uuid.New().String(),
	}

	authResponse, err := auth.Handler(context.TODO(), *authRequest)

	return &authResponse, err
}
