package alibabacloud

import (
	"context"
	"fmt"

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
	certID, ok := e.Data["identifier"].(string)
	if !ok {
		return fmt.Errorf("missing certificate identifier")
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
		h.uploadUserCertificate(ctx, cert, key, certID)
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
