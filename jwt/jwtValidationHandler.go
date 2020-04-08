package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"strconv"
	"strings"
	"time"
)

type JWTDataSe struct {
	Aud         string `json:"aud"`
	Sub         string `json:"sub"`
	Application struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Tier  string `json:"tier"`
		Owner string `json:"owner"`
	} `json:"application"`
	Scope          string `json:"scope"`
	Iss            string `json:"iss"`
	Keytype        string `json:"keytype"`
	SubscribedAPIs []struct {
		Name                   string `json:"name"`
		Context                string `json:"context"`
		Version                string `json:"version"`
		Publisher              string `json:"publisher"`
		SubscriptionTier       string `json:"subscriptionTier"`
		SubscriberTenantDomain string `json:"subscriberTenantDomain"`
	} `json:"subscribedAPIs"`
	ConsumerKey string `json:"consumerKey"`
	Exp         int    `json:"exp"`
	Iat         int64  `json:"iat"`
	Jti         string `json:"jti"`
}


const (
	StdPadding rune = '=' // Standard padding character
	NoPadding  rune = -1  // No padding
)

type JWTData struct {
	Aud         string `json:"aud"`
	Sub         string `json:"sub"`
	Application struct {
		Owner string      `json:"owner"`
		Tier  string      `json:"tier"`
		Name  string      `json:"name"`
		ID    int         `json:"id"`
		UUID  interface{} `json:"uuid"`
	} `json:"application"`
	Scope    string `json:"scope"`
	Iss      string `json:"iss"`
	TierInfo struct {
	} `json:"tierInfo"`
	Keytype        string        `json:"keytype"`
	SubscribedAPIs []struct {
		Name                   string `json:"name"`
		Context                string `json:"context"`
		Version                string `json:"version"`
		Publisher              string `json:"publisher"`
		SubscriptionTier       string `json:"subscriptionTier"`
		SubscriberTenantDomain string `json:"subscriberTenantDomain"`
	} `json:"subscribedAPIs"`
	ConsumerKey    string        `json:"consumerKey"`
	Exp            int64         `json:"exp"`
	Iat            int           `json:"iat"`
	Jti            string        `json:"jti"`
}

type Subscription struct {
	name                   string
	context                string
	version                string
	publisher              string
	subscriptionTier       string
	subscriberTenantDomain string
}

type TokenData struct {
	meta_clientType        string
	applicationConsumerKey string
	applicationName        string
	applicationId          string
	applicationOwner       string
	apiCreator             string
	apiCreatorTenantDomain string
	apiTier                string
	username               string
	userTenantDomain       string
	throttledOut           bool
	serviceTime            int64
	authorized             bool
}

var Unknown = "__unknown__"


var UnauthorizedError = errors.New("Invalid access token")


// handle JWT token
func HandleJWT(validateSubscription bool, publicCert []byte, requestAttributes map[string]string) (bool, TokenData, error) {

	accessToken := requestAttributes["authorization"]
	//apiName := requestAttributes["api-name"]
	//apiVersion := requestAttributes["api-version"]
	//requestScope := requestAttributes["request-scope"]

	tokenContent := strings.Split(accessToken, ".")
	var tokenData TokenData

	if len(tokenContent) != 3 {
		log.Errorf("Invalid JWT token received, token must have 3 parts")
		return false, tokenData, UnauthorizedError
	}

	signedContent := tokenContent[0] + "." + tokenContent[1]
	err := validateSignature(publicCert, signedContent, tokenContent[2])
	if err != nil {
		log.Errorf("Error in validating the signature: %v", err)
		return false, tokenData, UnauthorizedError
	}

	jwtData, err := decodePayload(tokenContent[1])
	if jwtData == nil {
		log.Errorf("Error in decoding the payload: %v", err)
		return false, tokenData, UnauthorizedError
	}

	if isTokenExpired(jwtData) {
		return false, tokenData, UnauthorizedError
	}

	//if !isRequestScopeValid(jwtData, requestScope) {
	//	return false, tokenData, UnauthorizedError
	//}

	if validateSubscription {

		subscription := getSubscription(jwtData, "", "")

		if (Subscription{}) == subscription {
			return false, tokenData, errors.New("Resource forbidden")
		}

		return true, getTokenDataForJWT(jwtData, "", ""), nil
	}

	return true, tokenData, nil
}

// validate the signature
func validateSignature(publicCert []byte, signedContent string, signature string) error {

	key, err := jwt.ParseRSAPublicKeyFromPEM(publicCert)

	if err != nil {
		log.Errorf("Error in parsing the public key: %v", err)
		return err
	}

	return jwt.SigningMethodRS256.Verify(signedContent, signature, key)
}

// decode the payload
func decodePayload(payload string) (*JWTData, error) {

	data, err := base64.StdEncoding.WithPadding(NoPadding).DecodeString(payload)

	jwtData := JWTData{}
	err = json.Unmarshal(data, &jwtData)
	if err != nil {
		log.Errorf("Error in unmarshalling payload: %v", err)
		return nil, err
	}

	return &jwtData, nil
}

// check whether the token has expired
func isTokenExpired(jwtData *JWTData) bool {

	nowTime := time.Now().Unix()
	expireTime := int64(jwtData.Exp)

	if expireTime < nowTime {
		log.Warnf("Token is expired!")
		return true
	}

	return false
}

// do resource scope validation
func isRequestScopeValid(jwtData *JWTData, requestScope string) bool {

	if len(requestScope) > 0 {

		tokenScopes := strings.Split(jwtData.Scope, " ")

		for _, tokenScope := range tokenScopes {
			if requestScope == tokenScope {
				return true
			}

		}
		log.Warnf("No matching scopes found!")
		return false
	}

	log.Infof("No scopes defined")
	return true
}

// get the subscription
func getSubscription(jwtData *JWTData, apiName string, apiVersion string) Subscription {

	var subscription Subscription
	for _, api := range jwtData.SubscribedAPIs {

		if (strings.ToLower(apiName) == strings.ToLower(api.Name)) && apiVersion == api.Version {
			subscription.name = apiName
			subscription.version = apiVersion
			subscription.context = api.Context
			subscription.publisher = api.Publisher
			subscription.subscriptionTier = api.SubscriptionTier
			subscription.subscriberTenantDomain = api.SubscriberTenantDomain
			return subscription
		}
	}

	log.Warnf("Subscription is not valid for API - %v %v", apiName, apiVersion)
	return subscription
}

// get token data for JWT
func getTokenDataForJWT(jwtData *JWTData, apiName string, apiVersion string) TokenData {

	var tokenData TokenData

	tokenData.authorized = true
	tokenData.meta_clientType = jwtData.Keytype
	tokenData.applicationConsumerKey = jwtData.ConsumerKey
	tokenData.applicationName = jwtData.Application.Name
	tokenData.applicationId = strconv.Itoa(jwtData.Application.ID)
	tokenData.applicationOwner = jwtData.Application.Owner

	subscription := getSubscription(jwtData, apiName, apiVersion)

	if &subscription == nil {
		tokenData.apiCreator = Unknown
		tokenData.apiCreatorTenantDomain = Unknown
		tokenData.apiTier = Unknown
		tokenData.userTenantDomain = Unknown
	} else {
		tokenData.apiCreator = subscription.publisher
		tokenData.apiCreatorTenantDomain = subscription.subscriberTenantDomain
		tokenData.apiTier = subscription.subscriptionTier
		tokenData.userTenantDomain = subscription.subscriberTenantDomain
	}

	tokenData.username = jwtData.Sub
	tokenData.throttledOut = false

	return tokenData
}


//reading the secret
func ReadFile(fileName string) ([]byte, error) {

	secretValue, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Warnf("Error in reading the file %v: error - %v", fileName, err)
	}

	return secretValue, err
}
