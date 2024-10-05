package endtoendtest

import (
	"fmt"
	"testing"

	car "cf-authorizer/authorizer"

	"github.com/stretchr/testify/assert"
)

func init() {
	car.InitLambda(Fixture.AwsConfig)
}

func Test_Authorize_Should_Succeed(t *testing.T) {
	authToken := fmt.Sprintf("Bearer %v", GetCanaryAccessToken())

	// authToken := fmt.Sprintf("Bearer %v", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkIzWFF2VFc1bE42a0ZGdUhOTU1XWiJ9.eyJpc3MiOiJodHRwczovL2Rldi1ncTdwYjdvazhpdmVqdWJvLnVzLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHw2NDRiMmE5NDQ0YTljMmYzNTQyMzA0NGYiLCJhdWQiOlsiaHR0cHM6Ly9kZXYtYXBpLmNsYXNzaWZpbmQuYXBwIiwiaHR0cHM6Ly9kZXYtZ3E3cGI3b2s4aXZlanViby51cy5hdXRoMC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNzIzMzMyMzM0LCJleHAiOjE3MjM0MTg3MzQsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJhenAiOiI3MVFkSjFURlk3NzdVNGNWb1pDUEpVWTJxV3RaNnZwNSJ9.ya76kcRQpgChZdjWCCgdmbdHRJccuQuyK3g9dEp4_7n338Q7UWqTny0DO1TYNDDsb6e7-qMhKZTCjrkcsCF-vIv8b21NiAd6RQMafgbSvEJIMWOechCrI9y2gqyQ7CB263LPRzr8gdb2iJB5VPrVp8doZCwoiPyli_yhnuhQT4OpUGVtJvUYdJwiRFrMeNnDKTi8P5L0HSDUOo7bm41n6MxwiYljp3G-0SG_X7jokOveC9M9A5gIkfPeGwdPybVcypRx22W6V0Fe-Oxgm9tmSZzHdLKCkmdywc5X6lowXm_uDhLqMDjb5FTSV1okTSD_BzrbBZs44TebMisgX1bOpw")

	authResponse, err := WhenWeSendAuthorizationToken(authToken)

	assert.Nil(t, err)
	assert.Equal(t, authResponse.PolicyDocument.Statement[0].Effect, "Allow")
	assert.NotNil(t, authResponse.Context["requesterId"])
	assert.NotNil(t, authResponse.Context["permissions"])
}
