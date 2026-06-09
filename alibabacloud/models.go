package alibabacloud

type responseMeta struct {
	RequestId string `json:"RequestId,omitempty"`
	HostId    string `json:"HostId,omitempty"`
	Code      string `json:"Code,omitempty"`
	Message   string `json:"Message,omitempty"`
	Recommend string `json:"Recommend,omitempty"`
}

type uploadUserCertificateRequest struct {
	Name string `json:"Name,omitempty"`
	Cert string `json:"Cert,omitempty"`
	Key  string `json:"Key,omitempty"`
}

type uploadUserCertificateResponse struct {
	responseMeta
	CertId     int64  `json:"CertId,omitempty"`
	ResourceId string `json:"ResourceId,omitempty"`
}

type esaListSitesRequest struct {
	Status string `json:"Status,omitempty"`
}

type esaListSitesResponse struct {
	responseMeta
	Sites []struct {
		SiteId   int64  `json:"SiteId,omitempty"`
		SiteName string `json:"SiteName,omitempty"`
	} `json:"Sites,omitempty"`
	TotalCount int32 `json:"TotalCount,omitempty"`
}

type ListCertificatesRequest struct {
	CertificateStatus string `json:"CertificateStatus,omitempty"`
	CertificateSource string `json:"CertificateSource,omitempty"`
}

type ListCertificatesResponse struct {
	responseMeta
	TotalCount      int64 `json:"TotalCount,omitempty"`
	CertificateList []struct {
		CertificateId int64 `json:"CertificateId,omitempty"`
	} `json:"CertificateList,omitempty"`
}

type setCertificateRequest struct {
	SiteId int64  `json:"SiteId,omitempty"`
	CasId  int64  `json:"CasId,omitempty"`
	Type   string `json:"Type,omitempty"`
	Region string `json:"Region,omitempty"`
	Id     string `json:"Id,omitempty"`
}

type setCertificateResponse struct {
	responseMeta
	Id string `json:"Id,omitempty"`
}

type listCertificatesByRecordRequest struct {
	SiteId     int64  `json:"SiteId,omitempty"`
	RecordName string `json:"RecordName,omitempty"`
	Detail     bool   `json:"Detail,omitempty"`
}

type listCertificatesByRecordResponse struct {
	responseMeta
	Result []struct {
		Certificates []listCertificatesByRecordResponseBodyResultCertificates `json:"Certificates,omitempty"`
	} `json:"Result,omitempty"`
	TotalCount int64 `json:"TotalCount,omitempty"`
}

type listCertificatesByRecordResponseBodyResultCertificates struct {
	SAN string `json:"SAN,omitempty"`
	Id  string `json:"Id,omitempty"`
}

type listCustomHostnamesRequest struct {
	SiteId int64  `json:"SiteId,omitempty"`
	Status string `json:"Status,omitempty"`
}

type ListCustomHostnamesResponse struct {
	responseMeta
	Hostnames []struct {
		HostnameId int64  `json:"HostnameId,omitempty"`
		Hostname   string `json:"Hostname,omitempty"`
		SslFlag    string `json:"SslFlag,omitempty"`
	} `json:"Hostnames,omitempty"`
	TotalCount int32 `json:"TotalCount,omitempty"`
}

type updateCustomHostnameRequest struct {
	HostnameId int64  `json:"HostnameId,omitempty"`
	SslFlag    string `json:"SslFlag,omitempty"`
	CertType   string `json:"CertType,omitempty"`
	CasId      int64  `json:"CasId,omitempty"`
	CasRegion  string `json:"CasRegion,omitempty"`
}

type updateCustomHostnameResponse struct {
	responseMeta
}
