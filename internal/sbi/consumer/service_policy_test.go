package consumer

import (
	"testing"

	"github.com/stretchr/testify/require"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/openapi/models"
)

// NF type admission is advertised to NRF for token issuance. It cannot be
// inferred from a token's subject (an NF instance ID) at the AUSF router.
func TestNausfAuthAdvertisesOnlyAllowedConsumers(t *testing.T) {
	service := models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH
	c := newTestConsumer(t, &ausf_context.AUSFContext{})
	profile, err := c.buildNfProfile(&ausf_context.AUSFContext{
		NfId: testNfId,
		NfService: map[models.Nrf_NFMgmt_ServiceName]models.Nrf_NFMgmt_NFService{
			service: {ServiceName: service},
		},
	})
	require.NoError(t, err)
	require.Len(t, profile.NfServices, 1)
	allowed := profile.NfServices[0].AllowedNfTypes
	require.ElementsMatch(t, []models.Nrf_NFMgmt_NFType{
		models.Nrf_NFMgmt_NFType_AMF, models.Nrf_NFMgmt_NFType_UDM,
	}, allowed)
	require.NotContains(t, allowed, models.Nrf_NFMgmt_NFType_SMF)
	copyOfPolicy, known := ausf_context.AllowedNfTypesForService(service)
	require.True(t, known)
	copyOfPolicy[0] = models.Nrf_NFMgmt_NFType_SMF
	unchanged, _ := ausf_context.AllowedNfTypesForService(service)
	require.ElementsMatch(t, allowed, unchanged)
}
