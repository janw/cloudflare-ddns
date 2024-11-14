package provider

import "github.com/favonia/cloudflare-ddns/internal/provider/protocol"

// NewLocalWithSuffix creates a protocol.LocalWithSuffix provider.
func NewLocalWithSuffix(suffix string) Provider {
	return protocol.LocalWithSuffix{
		ProviderName: "local.suffix:" + suffix,
		Suffix:       suffix,
	}
}
