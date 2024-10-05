package main

import (
	"github.com/aws/aws-lambda-go/lambda"

	logic "cf-authorizer/authorizer"
)

func main() {
	if logic.Authorizer == nil {
		logic.InitLambda(nil)
	}

	lambda.Start(logic.Handler)
}
