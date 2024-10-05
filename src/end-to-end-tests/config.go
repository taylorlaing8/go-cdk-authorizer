package endtoendtest

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/joho/godotenv"
)

type TestUtils struct {
	AwsConfig    *aws.Config
	TokenService *TokenService
	HTTPClient   *http.Client
}

var Fixture TestUtils

func init() {
	Fixture = loadConfig()
}

var TestIdentityGroupEntities []string = make([]string, 0)
var TestPermissionGroupEntities []string = make([]string, 0)
var TestAccessRoleEntities []string = make([]string, 0)

func loadConfig() TestUtils {
	utils := TestUtils{}

	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	service := os.Getenv("SERVICE")
	stage := os.Getenv("STAGE")
	region := os.Getenv("CDK_DEFAULT_REGION")

	stackName := fmt.Sprintf("%v-%v-app", service, stage)

	os.Setenv("AUTHORIZER_CONFIG_PATH", "/authorizer/config")
	os.Setenv("AUTH_CACHE_TABLE_NAME", fmt.Sprintf("%v-auth-cache", stackName))

	var cfg aws.Config

	cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		log.Panicf("Failed to load config: %v", err.Error())
	}

	cred, err := cfg.Credentials.Retrieve(context.TODO())
	if err != nil || !cred.HasKeys() {
		// Running locally - fetch credentials from profile
		profile := "cf-dev"

		cfg, _ = config.LoadDefaultConfig(context.TODO(),
			config.WithRegion(region),
			config.WithSharedConfigProfile(profile),
		)
		cred, err = cfg.Credentials.Retrieve(context.TODO())
		if err != nil || !cred.HasKeys() {
			log.Panicf("Failed to retrieve credentials for profile %v", profile)
		}
	}

	utils.AwsConfig = &cfg

	tokenService := loadTokenService(*utils.AwsConfig)
	utils.TokenService = &tokenService

	utils.HTTPClient = &http.Client{Timeout: time.Duration(15) * time.Second}

	return utils
}
