package context

import (
	"slices"

	"github.com/free5gc/openapi/models"
)

// servicePolicies defines the allowed NF types for each AUSF service.
// Allowed NFs: AMF (nausf-auth), UDM (all services).
var servicePolicies = map[models.Nrf_NFMgmt_ServiceName][]models.Nrf_NFMgmt_NFType{
	models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH: {
		models.Nrf_NFMgmt_NFType_AMF,
		// TS 29.509 5.2.2.3: UDM consumes Deregister to clear stale security contexts.
		models.Nrf_NFMgmt_NFType_UDM,
	},
	// TS 29.509 5.3 Nausf_SoRProtection and TS 33.501 Annex C.4: UDM requests
	// SoR protection from the AUSF.
	models.Nrf_NFMgmt_ServiceName_NAUSF_SORPROTECTION: {
		models.Nrf_NFMgmt_NFType_UDM,
	},
	// TS 29.509 5.4 Nausf_UPUProtection and TS 33.501 Annex C.5: UDM requests
	// UE Parameters Update protection from the AUSF.
	models.Nrf_NFMgmt_ServiceName_NAUSF_UPUPROTECTION: {
		models.Nrf_NFMgmt_NFType_UDM,
	},
}

// AllowedNfTypesForService returns a copy of the allowed NF types
// for the specified service and whether the service policy exists.
func AllowedNfTypesForService(serviceName models.Nrf_NFMgmt_ServiceName) (
	[]models.Nrf_NFMgmt_NFType, bool,
) {
	allowed, known := servicePolicies[serviceName]
	return slices.Clone(allowed), known
}
