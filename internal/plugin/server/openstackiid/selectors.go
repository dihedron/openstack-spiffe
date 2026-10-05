package openstackiid

import (
	"maps"
	"slices"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// SPIFFEID returns the agent SPIFFE ID for verified claims:
// spiffe://<trust_domain>/spire/agent/openstack_iid/<project_id>/<instance_id>.
// Both IDs have been validated, so they are well-formed path segments.
func SPIFFEID(trustDomain string, c iid.Claims) string {
	return "spiffe://" + trustDomain + "/spire/agent/" + iid.TargetName + "/" + c.ProjectID + "/" + c.InstanceID
}

// Selectors returns the selector values for verified claims. SPIRE infers
// the selector type from the plugin name, so the values carry no
// "openstack_iid:" prefix: "project_id:<id>" here is the selector
// "openstack_iid:project_id:<id>" in registration entries. Tag selectors come
// in key order; enrichment selectors only when the token carries the claim.
// Custom claims never become selectors: they are the same for every instance.
// Tags whose key is not in allowedTags are left out, unless allowedTags is nil
// (T-3): tags are set by the instance's owner, and the operator decides which
// of them registration entries may rely on.
func Selectors(c iid.Claims, allowedTags map[string]bool) []string {
	selectors := []string{
		"project_id:" + c.ProjectID,
		"instance_id:" + c.InstanceID,
		"hostname:" + c.Hostname,
	}
	for _, key := range slices.Sorted(maps.Keys(c.Tags)) {
		if allowedTags == nil || allowedTags[key] {
			selectors = append(selectors, "tag:"+key+":"+c.Tags[key])
		}
	}
	for _, e := range []struct{ name, value string }{
		{iid.ClaimAvailabilityZone, c.AvailabilityZone},
		{iid.ClaimFlavor, c.Flavor},
		{iid.ClaimUserID, c.UserID},
		{iid.ClaimProjectName, c.ProjectName},
		{iid.ClaimDomainID, c.DomainID},
	} {
		if e.value != "" {
			selectors = append(selectors, e.name+":"+e.value)
		}
	}
	return selectors
}
