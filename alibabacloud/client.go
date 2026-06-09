package alibabacloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// doRequest 执行通用的阿里云API请求
func (h *AlibabaCloudCertHandler) doRequest(ctx context.Context, host, method, action, version string, requestData any) ([]byte, error) {
	payload, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	endpointURL := fmt.Sprintf("https://%s/", host)
	req, err := http.NewRequestWithContext(ctx, method, endpointURL, bytes.NewReader(payload))
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

func (h *AlibabaCloudCertHandler) uploadUserCertificate(ctx context.Context, cert, key, name string) (*uploadUserCertificateResponse, error) {
	requestData := uploadUserCertificateRequest{
		Cert: cert,
		Key:  key,
		Name: name,
	}

	host := "cas.aliyuncs.com"            // ESA服务接入点
	xAcsAction := "UploadUserCertificate" // API名称
	xAcsVersion := "2020-04-07"           // API版本号

	body, err := h.doRequest(ctx, host, http.MethodGet, xAcsAction, xAcsVersion, requestData)
	if err != nil {
		return nil, err
	}

	var response uploadUserCertificateResponse

	if body == nil {
		return nil, fmt.Errorf("empty response body")
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &response, nil
}

func (h *AlibabaCloudCertHandler) esaListSites(ctx context.Context) (*esaListSitesResponse, error) {
	requestData := esaListSitesRequest{Status: "active"}

	// host := "esa.aliyuncs.com"  // ESA服务接入点
	host := "esa.cn-hangzhou.aliyuncs.com" // ESA服务接入点
	xAcsAction := "ListSites"              // API名称
	xAcsVersion := "2024-09-10"            // API版本号

	body, err := h.doRequest(ctx, host, http.MethodGet, xAcsAction, xAcsVersion, requestData)
	if err != nil {
		return nil, err
	}

	var response esaListSitesResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &response, nil
}

func (h *AlibabaCloudCertHandler) setCertificate(ctx context.Context, siteId, casId int64, id string) (*setCertificateResponse, error) {
	requestData := setCertificateRequest{
		SiteId: siteId,
		CasId:  casId,
		Type:   "cas",
		Region: "cn-hangzhou",
		Id:     id,
	}

	// host := "esa.aliyuncs.com"     // ESA服务接入点
	host := "esa.cn-hangzhou.aliyuncs.com" // ESA服务接入点
	xAcsAction := "SetCertificate"         // API名称
	xAcsVersion := "2024-09-10"            // API版本号

	body, err := h.doRequest(ctx, host, http.MethodPost, xAcsAction, xAcsVersion, requestData)
	if err != nil {
		return nil, err
	}

	var response setCertificateResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &response, nil
}

func (h *AlibabaCloudCertHandler) listCertificatesByRecord(ctx context.Context, siteId int64, recordName string) (*listCertificatesByRecordResponse, error) {
	requestData := listCertificatesByRecordRequest{
		SiteId:     siteId,
		RecordName: recordName,
		Detail:     true,
	}

	// host := "esa.aliyuncs.com"               // ESA服务接入点
	host := "esa.cn-hangzhou.aliyuncs.com"   // ESA服务接入点
	xAcsAction := "ListCertificatesByRecord" // API名称
	xAcsVersion := "2024-09-10"              // API版本号

	body, err := h.doRequest(ctx, host, http.MethodGet, xAcsAction, xAcsVersion, requestData)
	if err != nil {
		return nil, err
	}

	var response listCertificatesByRecordResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &response, nil
}

func (h *AlibabaCloudCertHandler) listCustomHostnames(ctx context.Context, siteId int64) (*ListCustomHostnamesResponse, error) {
	requestData := listCustomHostnamesRequest{
		SiteId: siteId,
	}

	// host := "esa.aliyuncs.com"               // ESA服务接入点
	host := "esa.cn-hangzhou.aliyuncs.com" // ESA服务接入点
	xAcsAction := "ListCustomHostnames"    // API名称
	xAcsVersion := "2024-09-10"            // API版本号

	body, err := h.doRequest(ctx, host, http.MethodGet, xAcsAction, xAcsVersion, requestData)
	if err != nil {
		return nil, err
	}

	var response ListCustomHostnamesResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &response, nil
}

func (h *AlibabaCloudCertHandler) updateCustomHostname(ctx context.Context, hostnameId int64, sslFlag string, casId int64) (*updateCustomHostnameResponse, error) {
	requestData := updateCustomHostnameRequest{
		HostnameId: hostnameId,
		SslFlag:    sslFlag,
		CertType:   "cas",
		CasId:      casId,
		CasRegion:  "cn-hangzhou",
	}

	// host := "esa.aliyuncs.com"               // ESA服务接入点
	host := "esa.cn-hangzhou.aliyuncs.com" // ESA服务接入点
	xAcsAction := "UpdateCustomHostname"   // API名称
	xAcsVersion := "2024-09-10"            // API版本号

	body, err := h.doRequest(ctx, host, http.MethodPost, xAcsAction, xAcsVersion, requestData)
	if err != nil {
		return nil, err
	}

	var response updateCustomHostnameResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &response, nil
}
