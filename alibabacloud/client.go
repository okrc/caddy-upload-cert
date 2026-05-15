package alibabacloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"go.uber.org/zap"
)

// doRequest 执行通用的阿里云API请求
func (h *AlibabaCloudCertHandler) doRequest(ctx context.Context, host, action, version string, requestData interface{}) ([]byte, error) {
	payload, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	endpointURL := fmt.Sprintf("https://%s/", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Host = host

	// 调用签名函数
	err = AlibabaCloudSigner(h.AccessKeyID, h.AccessKeySecret, h.SecurityToken, req, action, version)
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (h *AlibabaCloudCertHandler) uploadUserCertificate(ctx context.Context, cert, key, name string) (string, error) {
	requestData := uploadUserCertificateRequest{
		Cert: &cert,
		Key:  &key,
		Name: &name,
	}

	host := "cas.aliyuncs.com"            // ESA服务接入点
	xAcsAction := "UploadUserCertificate" // API名称
	xAcsVersion := "2020-04-07"           // API版本号

	body, err := h.doRequest(ctx, host, xAcsAction, xAcsVersion, requestData)
	if err != nil {
		return "", err
	}

	var response uploadUserCertificateResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if response.Body == nil || response.Body.CertId == nil {
		return "", fmt.Errorf("invalid response: missing CertId")
	}

	certID := fmt.Sprintf("%d", *response.Body.CertId)
	h.logger.Info("Successfully uploaded certificate to Alibaba Cloud", zap.String("cert_id", certID), zap.String("name", name))

	return certID, nil
}
