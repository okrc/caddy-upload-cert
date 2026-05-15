package tencentcloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	sslService = "ssl"
	apiVersion = "2019-12-05"
	region     = ""
)

func tencentCloudSigner(secretId string, secretKey string, r *http.Request, action string, payload string, service string) {
	token := ""
	host := service + ".tencentcloudapi.com"
	algorithm := "TC3-HMAC-SHA256"
	var timestamp = time.Now().Unix()

	// step 1: build canonical request string
	httpRequestMethod := "POST"
	canonicalURI := "/"
	canonicalQueryString := ""
	contentType := "application/json; charset=utf-8"
	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-tc-action:%s\n",
		contentType, host, strings.ToLower(action))
	signedHeaders := "content-type;host;x-tc-action"
	hashedRequestPayload := sha256Hex(payload)
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		httpRequestMethod,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		hashedRequestPayload)

	// step 2: build string to sign
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, service)
	hashedCanonicalRequest := sha256Hex(canonicalRequest)
	string2sign := fmt.Sprintf("%s\n%d\n%s\n%s",
		algorithm,
		timestamp,
		credentialScope,
		hashedCanonicalRequest)

	// step 3: sign string
	secretDate := hmacSha256(date, "TC3"+secretKey)
	secretService := hmacSha256(service, secretDate)
	secretSigning := hmacSha256("tc3_request", secretService)
	signature := hex.EncodeToString([]byte(hmacSha256(string2sign, secretSigning)))

	// step 4: build authorization
	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		secretId,
		credentialScope,
		signedHeaders,
		signature)

	r.Header.Set("Host", host)
	r.Header.Set("X-TC-Action", action)
	r.Header.Set("X-TC-Version", apiVersion)
	r.Header.Set("X-TC-Timestamp", strconv.FormatInt(timestamp, 10))
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("Authorization", authorization)
	if region != "" {
		r.Header.Set("X-TC-Region", region)
	}
	if token != "" {
		r.Header.Set("X-TC-Token", token)
	}
}

func sha256Hex(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

func hmacSha256(s, key string) string {
	hashed := hmac.New(sha256.New, []byte(key))
	hashed.Write([]byte(s))
	return string(hashed.Sum(nil))
}
