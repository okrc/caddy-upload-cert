package tencentcloud

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// init registers the Tencent Cloud certificate upload handler module with Caddy
func init() {
	caddy.RegisterModule(TencentCloudCertHandler{})
}

// TencentCloudCertHandler handles automatic certificate upload to Tencent Cloud
type TencentCloudCertHandler struct {
	// SecretId is the Tencent Cloud API access key ID for authentication
	SecretId string `json:"secret_id"`
	// SecretKey is the Tencent Cloud API access key for signature verification
	SecretKey string `json:"secret_key"`
	// AllowList specifies which domains are allowed to upload certificates
	AllowList []string `json:"allow_list,omitempty"`
	// BlockList specifies which domains are blocked from uploading certificates
	BlockList []string `json:"block_list,omitempty"`
	// TryDeleteOldCert determines whether to delete old certificates when updating
	TryDeleteOldCert bool `json:"try_delete_old_cert,omitempty"`

	ctx     caddy.Context
	logger  *zap.Logger
	storage certmagic.Storage
}

func (TencentCloudCertHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "events.handlers.upload_cert_tencentcloud",
		New: func() caddy.Module { return new(TencentCloudCertHandler) },
	}
}

func (h *TencentCloudCertHandler) Provision(ctx caddy.Context) error {
	h.ctx = ctx
	h.logger = ctx.Logger(h)
	h.storage = ctx.Storage()

	return nil
}

func (h *TencentCloudCertHandler) Handle(ctx context.Context, e caddy.Event) error {
	if e.Name() != "cert_obtained" {
		h.logger.Warn("upload_cert_tencentcloud should only be handled on `cert_obtained`, ignoring", zap.String("event", e.Name()))
		return nil
	}
	certID, ok := e.Data["identifier"].(string)
	if !ok {
		return fmt.Errorf("missing certificate identifier")
	}
	if slices.Contains(h.BlockList, certID) || len(h.AllowList) > 0 && !slices.Contains(h.AllowList, certID) {
		h.logger.Info(fmt.Sprintf("upload_cert_tencentcloud ignored certificate %s not matching the current rule", certID), zap.String("event", e.Name()))
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
		certificateId, _ := h.DescribeCertificates(ctx, certID)
		if certificateId == "" {
			if err := h.UploadCertificate(ctx, cert, key); err != nil {
				h.logger.Error("upload certificate failed", zap.String("certificate", certID), zap.Error(err))
				return
			}
		} else {
			var deployRecordId uint64
			for i := 0; i < 60 && deployRecordId == 0; i++ {
				if err := h.UpdateCertificateInstance(ctx, cert, key, certificateId, &deployRecordId); err != nil {
					if err := h.UploadCertificate(ctx, cert, key); err != nil {
						h.logger.Error("upload certificate after update failure failed", zap.String("certificate", certID), zap.Error(err))
						return
					}
					deployRecordId = 1
				}
				time.Sleep(5 * time.Second)
			}
			if deployRecordId == 0 {
				h.logger.Error("failed to update certificate instance", zap.Error(err))
				return
			}
			if h.TryDeleteOldCert {
				if err := h.DeleteCertificate(ctx, certificateId); err != nil {
					h.logger.Warn("failed to delete old certificate", zap.String("certificateId", certificateId), zap.Error(err))
				} else {
					h.logger.Info("successfully deleted old certificate", zap.String("certificateId", certificateId))
				}
			}
		}
		h.logger.Info("successfully uploaded certificate to Tencent Cloud",
			zap.String("certificate", certID),
			zap.String("event", e.Name()),
		)
	}()
	return nil
}

func (h *TencentCloudCertHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "secret_id":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.SecretId = d.Val()
			case "secret_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.SecretKey = d.Val()
			case "allow_list":
				h.AllowList = append(h.AllowList, d.RemainingArgs()...)
			case "block_list":
				h.BlockList = append(h.BlockList, d.RemainingArgs()...)
			case "try_delete_old_cert":
				if d.NextArg() {
					return d.ArgErr()
				}
				h.TryDeleteOldCert = true
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
			if d.NextArg() {
				return d.ArgErr()
			}
		}
	}
	if h.SecretId == "" || h.SecretKey == "" {
		return d.Err("SecretId or SecretKey is empty")
	}
	return nil
}

// Interface guards
var (
	_ caddy.Module          = (*TencentCloudCertHandler)(nil)
	_ caddy.Provisioner     = (*TencentCloudCertHandler)(nil)
	_ caddyevents.Handler   = (*TencentCloudCertHandler)(nil)
	_ caddyfile.Unmarshaler = (*TencentCloudCertHandler)(nil)
)
