package agent

import (
	"log/slog"

	"github.com/tollwing/tollwing/pkg/cloud"
)

// newCloudProvider supplies non-AWS cloud providers for the agent's topology
// and rate-card refreshers. The open-source build is AWS-only, so it always
// reports unavailable; the Enterprise build (-tags enterprise) registers GCP
// and Azure in cloud_enterprise.go.
//
// Keeping the gcp/azure provider packages out of the OSS build is the Path-1
// open-core split: multi-cloud is an Enterprise capability, and its provider
// code is not shipped in the public tree.
func newCloudProvider(provider, region, zone string, log *slog.Logger) (cloud.Provider, bool) {
	return nil, false
}
