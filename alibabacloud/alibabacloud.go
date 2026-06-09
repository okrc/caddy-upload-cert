package alibabacloud

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// init registers the Alibaba Cloud certificate upload handler module with Caddy
func init() {
	caddy.RegisterModule(AlibabaCloudCertHandler{})
}

// AlibabaCloudCertHandler handles automatic certificate upload to Alibaba Cloud
type AlibabaCloudCertHandler struct {
	// The API Key ID Required by Aliyun's for accessing the Aliyun's API
	AccessKeyID string `json:"access_key_id"`
	// The API Key Secret Required by Aliyun's for accessing the Aliyun's API
	AccessKeySecret string `json:"access_key_secret"`
	// Optional for identifing the region of the Aliyun's Service,The default is zh-hangzhou
	RegionID string `json:"region_id,omitempty"`
	// The Security Token Required If you enabled the Aliyun's STS(SecurityToken) for accessing the Aliyun's API
	SecurityToken string `json:"security_token,omitempty"`
	// AllowList specifies which domains are allowed to upload certificates
	AllowList []string `json:"allow_list,omitempty"`
	// BlockList specifies which domains are blocked from uploading certificates
	BlockList []string `json:"block_list,omitempty"`
	// DeleteExpiredCert determines whether to expired old certificates when updating
	DeleteExpiredCert bool `json:"delete_expired_cert,omitempty"`

	ctx     caddy.Context
	logger  *zap.Logger
	storage certmagic.Storage
}

func (AlibabaCloudCertHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "events.handlers.upload_cert_alibabacloud",
		New: func() caddy.Module { return new(AlibabaCloudCertHandler) },
	}
}

func (h *AlibabaCloudCertHandler) Provision(ctx caddy.Context) error {
	h.ctx = ctx
	h.logger = ctx.Logger(h)
	h.storage = ctx.Storage()

	return nil
}

func (h *AlibabaCloudCertHandler) Handle(ctx context.Context, e caddy.Event) error {
	if e.Name() != "cert_obtained" {
		h.logger.Warn("upload_cert_alibabacloud should only be handled on `cert_obtained`, ignoring", zap.String("event", e.Name()))
		return nil
	}
	identifier, ok := e.Data["identifier"].(string)
	if !ok {
		return fmt.Errorf("missing certificate identifier")
	}
	if slices.Contains(h.BlockList, identifier) || len(h.AllowList) > 0 && !slices.Contains(h.AllowList, identifier) {
		h.logger.Info(fmt.Sprintf("upload_cert_alibabacloud ignored certificate %s not matching the current rule", identifier), zap.String("event", e.Name()))
		return nil
	}
	certificatePath, ok := e.Data["certificate_path"].(string)
	if !ok {
		return fmt.Errorf("missing certificate path")
	}
	privateKeyPath, ok := e.Data["private_key_path"].(string)
	if !ok {
		return fmt.Errorf("missing private key path")
	}

	loadCert := func(path string) (string, error) {
		bytes, err := h.storage.Load(ctx, path)
		if err != nil {
			return "", fmt.Errorf("failed to load file: %s", path)
		}
		return string(bytes), nil
	}

	cert, err := loadCert(certificatePath)
	if err != nil {
		return err
	}
	key, err := loadCert(privateKeyPath)
	if err != nil {
		return err
	}

	go func() {
		certName := fmt.Sprintf("%s_%s", identifier, time.Now().Format("06-01-02_15:04:05"))
		response, err := h.uploadUserCertificate(ctx, cert, key, certName)
		if err != nil || response == nil {
			h.logger.Error("upload certificate failed",
				zap.String("certificate", identifier),
				zap.String("RequestId", response.RequestId),
				zap.String("HostId", response.HostId),
				zap.String("Code", response.Code),
				zap.String("Message", response.Message),
				zap.String("Recommend", response.Recommend),
				zap.Error(err))
			return
		}
		casId := response.CertId

		h.logger.Info("Successfully uploaded certificate to Alibaba Cloud",
			zap.Int64("CertId", casId),
			zap.String("Name", certName),
			zap.String("RequestId", response.RequestId),
		)

		listSites, err := h.esaListSites(ctx)
		if err != nil {
			h.logger.Error("list sites failed", zap.Error(err))
			return
		}
		if listSites == nil {
			h.logger.Error("list sites failed")
			return
		}
		h.logger.Info("upload certificate",
			zap.Int32("TotalCount", listSites.TotalCount),
		)
		for _, site := range listSites.Sites {
			if site.SiteName == identifier || strings.HasSuffix(identifier, "."+site.SiteName) {
				s, _ := h.listCertificatesByRecord(ctx, site.SiteId, identifier)
				if s == nil {
					h.logger.Error("list certificates by record failed")
					return
				}
				h.logger.Info("list certificate by record",
					zap.Int64("TotalCount", s.TotalCount),
				)
				for _, cert := range s.Result {
					for _, ss := range cert.Certificates {
						h.logger.Info("list certificate by record",
							zap.String("san", ss.SAN),
							zap.String("id", ss.Id),
							zap.String("RequestId", s.RequestId),
						)
						if ss.SAN == identifier {
							ab, err := h.setCertificate(ctx, site.SiteId, casId, ss.Id)
							if err != nil {
								h.logger.Error("set certificate failed",
									zap.Error(err),
								)
								if ab != nil {
									h.logger.Error("set certificate failed",
										zap.String("RequestId", ab.RequestId),
										zap.String("HostId", ab.HostId),
										zap.String("Code", ab.Code),
										zap.String("Message", ab.Message),
										zap.String("Recommend", ab.Recommend),
									)
								}
								return
							}
							h.logger.Info("set certificate",
								zap.String("Id", ab.Id),
								zap.String("RequestId", ab.RequestId),
							)
						}
					}
				}
			}

			saas, err := h.listCustomHostnames(ctx, site.SiteId)
			if err != nil {
				h.logger.Error("list custom hostnames failed", zap.Error(err))
				return
			}
			if saas == nil {
				h.logger.Error("list custom hostnames failed")
				return
			}
			for _, sa := range saas.Hostnames {
				if certmagic.MatchWildcard(sa.Hostname, identifier) {
					u, err := h.updateCustomHostname(ctx, sa.HostnameId, sa.SslFlag, casId)
					if err != nil {
						h.logger.Error("update custom hostname failed",
							zap.Error(err),
						)
					}
					if u == nil {
						h.logger.Error("update custom hostname failed")
						return
					}
					h.logger.Info("update custom hostname",
						zap.String("Hostname", sa.Hostname),
						zap.Int64("HostnameId", sa.HostnameId),
						zap.String("SslFlag", sa.SslFlag),
						zap.String("RequestId", u.RequestId),
					)
				}
			}
		}
	}()

	return nil
}

func (h *AlibabaCloudCertHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "access_key_id":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.AccessKeyID = d.Val()
			case "access_key_secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.AccessKeySecret = d.Val()
			case "region_id":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.RegionID = d.Val()
			case "security_token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.SecurityToken = d.Val()
			case "allow_list":
				h.AllowList = append(h.AllowList, d.RemainingArgs()...)
			case "block_list":
				h.BlockList = append(h.BlockList, d.RemainingArgs()...)
			case "delete_expired_cert":
				if d.NextArg() {
					return d.ArgErr()
				}
				h.DeleteExpiredCert = true
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
			if d.NextArg() {
				return d.ArgErr()
			}
		}
	}
	if h.AccessKeyID == "" || h.AccessKeySecret == "" {
		return d.Err("AccessKeyID or AccessKeySecret is empty")
	}
	return nil
}

// Interface guards
var (
	_ caddy.Module          = (*AlibabaCloudCertHandler)(nil)
	_ caddy.Provisioner     = (*AlibabaCloudCertHandler)(nil)
	_ caddyevents.Handler   = (*AlibabaCloudCertHandler)(nil)
	_ caddyfile.Unmarshaler = (*AlibabaCloudCertHandler)(nil)
)
