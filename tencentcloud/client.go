package tencentcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

var (
	repeatable                        = false
	allowDownload                     = false
	expiringNotificationSwitch uint64 = 1
)

func (h *TencentCloudCertHandler) DescribeCertificates(ctx context.Context, domain string) (string, error) {
	requestData := DescribeCertificatesRequest{
		SearchKey:       domain,
		CertificateType: "SVR",
		FilterSource:    "upload",
	}
	payload, err := json.Marshal(requestData)
	if err != nil {
		return "", err
	}
	resp, err := h.doAPIRequest(ctx, "DescribeCertificates", string(payload))
	if err != nil {
		return "", err
	}
	var response DescribeCertificatesResponse
	if err = json.Unmarshal(resp, &response); err != nil {
		return "", err
	}
	if response.Response.Error != nil {
		return "", fmt.Errorf("%s", response.Response.Error.Message)
	}
	for _, cert := range response.Response.Certificates {
		if len(cert.SubjectAltName) == 1 && slices.Contains(cert.SubjectAltName, domain) {
			return cert.CertificateId, nil
		}
	}
	return "", nil
}

func (h *TencentCloudCertHandler) UploadCertificate(ctx context.Context, publicKey, privateKey string) error {
	requestData := UploadCertificateRequest{
		CertificatePublicKey:  publicKey,
		CertificatePrivateKey: privateKey,
		CertificateType:       "SVR",
		Repeatable:            &repeatable,
	}
	payload, err := json.Marshal(requestData)
	if err != nil {
		return err
	}
	resp, err := h.doAPIRequest(ctx, "UploadCertificate", string(payload))
	if err != nil {
		return err
	}
	var response UploadCertificateResponse
	if err = json.Unmarshal(resp, &response); err != nil {
		return err
	}
	if response.Response.Error != nil {
		return fmt.Errorf("%s", response.Response.Error.Message)
	}
	return nil
}

func (h *TencentCloudCertHandler) UpdateCertificateInstance(ctx context.Context, publicKey, privateKey, id string, DeployRecordId *uint64) error {
	requestData := UpdateCertificateInstanceRequest{
		OldCertificateId: id,
		ResourceTypes: []string{
			"clb", "cdn", "waf", "live", "ddos", "teo",
			"apigateway", "vod", "tke", "tcb", "tse", "cos",
			"mqtt", "scf", "tdmq", "gaap",
		},
		CertificatePublicKey:       publicKey,
		CertificatePrivateKey:      privateKey,
		ExpiringNotificationSwitch: expiringNotificationSwitch,
		Repeatable:                 &repeatable,
		AllowDownload:              &allowDownload,
	}
	payload, err := json.Marshal(requestData)
	if err != nil {
		return err
	}
	resp, err := h.doAPIRequest(ctx, "UpdateCertificateInstance", string(payload))
	if err != nil {
		return err
	}
	var response UpdateCertificateInstanceResponse
	if err = json.Unmarshal(resp, &response); err != nil {
		return err
	}
	if response.Response.Error != nil {
		return fmt.Errorf("%s", response.Response.Error.Message)
	}
	*DeployRecordId = response.Response.DeployRecordId
	return nil
}

// 当前为白名单功能，非白名单用户无法使用该功能，请联系SSL证书特殊处理。
// func (h *TencentCloudCertHandler) UploadUpdateCertificateInstance(ctx context.Context, publicKey, privateKey, id string) error {
// 	requestData := UploadUpdateCertificateInstanceRequest{
// 		OldCertificateId:      id,
// 		ResourceTypes:         []string{"clb"},
// 		CertificatePublicKey:  publicKey,
// 		CertificatePrivateKey: privateKey,
// 	}
// 	payload, err := json.Marshal(requestData)
// 	if err != nil {
// 		return err
// 	}
// 	resp, err := h.doAPIRequest(ctx, "UploadUpdateCertificateInstance", string(payload))
// 	if err != nil {
// 		return err
// 	}
// 	var response UploadUpdateCertificateInstanceResponse
// 	if err = json.Unmarshal(resp, &response); err != nil {
// 		return err
// 	}
// 	if response.Response.Error != nil {
// 		return fmt.Errorf("%s", response.Response.Error.Message)
// 	}
// 	return nil
// }

func (h *TencentCloudCertHandler) DeleteCertificate(ctx context.Context, id string) error {
	requestData := DeleteCertificateRequest{
		CertificateId: id,
	}
	payload, err := json.Marshal(requestData)
	if err != nil {
		return err
	}
	resp, err := h.doAPIRequest(ctx, "DeleteCertificate", string(payload))
	if err != nil {
		return err
	}
	var response DeleteCertificateResponse
	if err = json.Unmarshal(resp, &response); err != nil {
		return err
	}
	if response.Response.Error != nil {
		return fmt.Errorf("%s", response.Response.Error.Message)
	}
	return nil
}

func (h *TencentCloudCertHandler) doAPIRequest(ctx context.Context, action, data string) ([]byte, error) {
	endpointUrl := fmt.Sprintf("https://%s.tencentcloudapi.com", sslService)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointUrl, strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	tencentCloudSigner(h.SecretId, h.SecretKey, req, action, data, sslService)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
