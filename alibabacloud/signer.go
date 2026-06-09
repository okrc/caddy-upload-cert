package alibabacloud

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

const ALGORITHM = "ACS3-HMAC-SHA256"

func AlibabaCloudSigner(accessKeyId, accessKeySecret, securityToken string, req *http.Request, xAcsAction, xAcsVersion string) error {
	// 1. 基础 Header 注入
	req.Header.Set("x-acs-action", xAcsAction)
	req.Header.Set("x-acs-version", xAcsVersion)
	req.Header.Set("x-acs-date", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("x-acs-signature-nonce", uuid.New().String())
	if securityToken != "" {
		req.Header.Set("x-acs-security-token", securityToken)
	}

	// 2. 处理 Body 并计算 Content-SHA256
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	// 优化：sha256Hex 直接接收字节数组，避免 string(bodyBytes) 的内存拷贝
	hashedRequestPayload := sha256Hex(bodyBytes)
	req.Header.Set("x-acs-content-sha256", hashedRequestPayload)

	// 3. 步骤 1：拼接规范请求串
	canonicalQueryString := getCanonicalQueryString(req.URL.Query())
	canonicalHeaders, signedHeaders := getCanonicalHeaders(req.Header)

	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		hashedRequestPayload,
	}, "\n")

	// 4. 步骤 2：拼接待签名字符串
	hashedCanonicalRequest := sha256Hex([]byte(canonicalRequest))
	stringToSign := ALGORITHM + "\n" + hashedCanonicalRequest

	// 5. 步骤 3：计算签名 (修正：必须返回十六进制小写字符串)
	signature := hmacSha256(accessKeySecret, stringToSign)

	// 6. 步骤 4：设置 Authorization Header (修正：key 必须是 Signature 而不是 signatureBytes)
	authValue := fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
		ALGORITHM, accessKeyId, signedHeaders, signature)
	req.Header.Set("Authorization", authValue)

	return nil
}

func getCanonicalQueryString(query url.Values) string {
	if len(query) == 0 {
		return ""
	}
	// 优化：使用 Go 1.23 现代写法
	keys := slices.AppendSeq(make([]string, 0, len(query)), maps.Keys(query))
	slices.Sort(keys)

	var parts []string
	for _, k := range keys {
		v := query.Get(k)
		part := percentCode(url.QueryEscape(k)) + "=" + percentCode(url.QueryEscape(v))
		parts = append(parts, part)
	}
	return strings.Join(parts, "&")
}

func getCanonicalHeaders(headers http.Header) (string, string) {
	keys := slices.AppendSeq(make([]string, 0, len(headers)), maps.Keys(headers))
	slices.Sort(keys)

	var canonicalHeaderBuf strings.Builder
	var signedHeaderKeys []string

	for _, k := range keys {
		lowerKey := strings.ToLower(k)
		if lowerKey == "host" || lowerKey == "content-type" || strings.HasPrefix(lowerKey, "x-acs-") {
			val := strings.TrimSpace(headers.Get(k))
			canonicalHeaderBuf.WriteString(lowerKey + ":" + val + "\n")
			signedHeaderKeys = append(signedHeaderKeys, lowerKey)
		}
	}

	return canonicalHeaderBuf.String(), strings.Join(signedHeaderKeys, ";")
}

func hmacSha256(key, s string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func percentCode(str string) string {
	str = strings.ReplaceAll(str, "+", "%20")
	str = strings.ReplaceAll(str, "*", "%2A")
	str = strings.ReplaceAll(str, "%7E", "~")
	return str
}
