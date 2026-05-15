package alibabacloud

const (
	aliesaEndpoint string = "https://esa.cn-hangzhou.aliyuncs.com/"
)

type responseMeta struct {
	Headers    map[string]*string `json:"headers,omitempty"`
	StatusCode *int32             `json:"statusCode,omitempty"`
}

type uploadUserCertificateRequest struct {
	Name *string `json:"Name,omitempty"`
	Cert *string `json:"Cert,omitempty"`
	Key  *string `json:"Key,omitempty"`
}

type uploadUserCertificateResponse struct {
	responseMeta
	Body *uploadUserCertificateResponseBody `json:"body,omitempty"`
}

type uploadUserCertificateResponseBody struct {
	CertId     *int64  `json:"CertId,omitempty"`
	RequestId  *string `json:"RequestId,omitempty"`
	ResourceId *string `json:"ResourceId,omitempty"`
}
