package tencentcloud

type Error struct {
	Code    string `json:"Code,omitempty"`
	Message string `json:"Message,omitempty"`
}

type ResponseMeta struct {
	Error     *Error `json:"Error,omitempty"`
	RequestId string `json:"RequestId,omitempty"`
}

type DescribeCertificatesRequest struct {
	SearchKey       string `json:"SearchKey,omitempty"`
	CertificateType string `json:"CertificateType,omitempty"`
	FilterSource    string `json:"FilterSource,omitempty"`
}

type DescribeCertificatesResponse struct {
	Response struct {
		ResponseMeta
		TotalCount   uint64        `json:"TotalCount,omitempty"`
		Certificates []Certificate `json:"Certificates,omitempty"`
	}
}

type UpdateCertificateInstanceRequest struct {
	OldCertificateId           string   `json:"OldCertificateId,omitempty"`
	ResourceTypes              []string `json:"ResourceTypes,omitempty"`
	CertificatePublicKey       string   `json:"CertificatePublicKey,omitempty"`
	CertificatePrivateKey      string   `json:"CertificatePrivateKey,omitempty"`
	ExpiringNotificationSwitch uint64   `json:"ExpiringNotificationSwitch,omitempty"`
	Repeatable                 *bool    `json:"Repeatable,omitempty"`
	AllowDownload              *bool    `json:"AllowDownload,omitempty"`
}

type UpdateCertificateInstanceResponse struct {
	Response struct {
		ResponseMeta
		DeployRecordId     uint64               `json:"DeployRecordId,omitempty"`
		DeployStatus       int64                `json:"DeployStatus,omitempty"`
		UpdateSyncProgress []UpdateSyncProgress `json:"UpdateSyncProgress,omitempty"`
	}
}

type UploadCertificateRequest struct {
	CertificatePublicKey  string `json:"CertificatePublicKey,omitempty"`
	CertificatePrivateKey string `json:"CertificatePrivateKey,omitempty"`
	CertificateType       string `json:"CertificateType,omitempty"`
	Repeatable            *bool  `json:"Repeatable,omitempty"`
}

type UploadCertificateResponse struct {
	Response struct {
		ResponseMeta
		CertificateId string `json:"CertificateId,omitempty"`
		RepeatCertId  string `json:"RepeatCertId,omitempty"`
	}
}

// 当前为白名单功能，非白名单用户无法使用该功能，请联系SSL证书特殊处理。
// type UploadUpdateCertificateInstanceRequest struct {
// 	OldCertificateId      string   `json:"OldCertificateId,omitempty"`
// 	ResourceTypes         []string `json:"ResourceTypes,omitempty"`
// 	CertificatePublicKey  string   `json:"CertificatePublicKey,omitempty"`
// 	CertificatePrivateKey string   `json:"CertificatePrivateKey,omitempty"`
// }

// type UploadUpdateCertificateInstanceResponse struct {
// 	Response struct {
// 		ResponseMeta
// 		DeployRecordId     uint64               `json:"DeployRecordId,omitempty"`
// 		DeployStatus       int64                `json:"DeployStatus,omitempty"`
// 		UpdateSyncProgress []UpdateSyncProgress `json:"UpdateSyncProgress,omitempty"`
// 	}
// }

type DeleteCertificateRequest struct {
	CertificateId   string `json:"CertificateId,omitempty"`
	IsCheckResource bool   `json:"IsCheckResource,omitempty"`
}

type DeleteCertificateResponse struct {
	Response struct {
		ResponseMeta
		DeleteResult bool   `json:"DeleteResult,omitempty"`
		TaskId       string `json:"TaskId,omitempty"`
	}
}

type UpdateSyncProgress struct {
	ResourceType              string                     `json:"ResourceType,omitempty"`
	UpdateSyncProgressRegions []UpdateSyncProgressRegion `json:"UpdateSyncProgressRegions,omitempty"`
	Status                    int64                      `json:"Status,omitempty"`
}

type UpdateSyncProgressRegion struct {
	Region      string `json:"Region,omitempty"`
	TotalCount  int64  `json:"TotalCount,omitempty"`
	OffsetCount int64  `json:"OffsetCount,omitempty"`
	Status      int64  `json:"Status,omitempty"`
}

type Certificate struct {
	CertificateId  string   `json:"CertificateId,omitempty"`
	SubjectAltName []string `json:"SubjectAltName,omitempty"`
}
