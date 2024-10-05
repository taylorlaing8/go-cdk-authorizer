package endtoendtest

func GetCanaryAccessToken() string {
	return Fixture.TokenService.GetAccessToken()
}
