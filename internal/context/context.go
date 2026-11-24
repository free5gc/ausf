package context

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
)

type AUSFContext struct {
	// UePool holds the context of each subscriber's last confirmed
	// authentication, by SUPI.
	UePool sync.Map
	// authCtxs holds the authentications that are not confirmed yet, by
	// authCtxId, and authCtxExpiries the same entries in the order they were
	// added.
	authCtxMu            sync.Mutex
	authCtxs             map[string]*authCtx
	authCtxExpiries      []authCtxExpiry
	NfId                 string
	GroupID              string
	SBIPort              int
	RegisterIPv4         string
	BindingIPv4          string
	Url                  string
	UriScheme            models.UriScheme
	NrfUri               string
	NrfCertPem           string
	NrfNfInstanceID      string
	NfService            map[models.Nrf_NFMgmt_ServiceName]models.Nrf_NFMgmt_NFService
	PlmnList             []models.PlmnId
	UdmUeauUrl           string
	snRegex              *regexp.Regexp
	EapAkaSupiImsiPrefix bool
	OAuth2Required       bool
}

type AusfUeContext struct {
	Supi               string
	Kausf              string
	Kseaf              string
	ServingNetworkName string
	AuthType           models.Ausf_UEAU_AuthType
	AuthStatus         models.Ausf_UEAU_AuthResult
	UdmUeauUrl         string
	// ConfirmedAt lets the background reaper find confirmed contexts that
	// were never cleared by an explicit Deregister call.
	ConfirmedAt time.Time

	// for 5G AKA
	XresStar string

	// for EAP-AKA'
	K_aut    string
	XRES     string
	Rand     string
	EapID    uint8
	Resynced bool
}

type authCtx struct {
	ue      *AusfUeContext
	expires time.Time
}

type authCtxExpiry struct {
	authCtxId string
	ctx       *authCtx
}

// authCtxLifetime is how long an authentication that is not confirmed is kept
// after it was added. The AMF aborts an authentication procedure at the fifth
// expiry of T3560 (6 s, TS 24.501 clause 5.4.1.3.7); an EAP-AKA' session can
// take two such exchanges.
const authCtxLifetime = 2 * time.Minute

// now is the clock of authCtxLifetime; tests replace it.
var now = time.Now

type EapAkaPrimeAttribute struct {
	Type   uint8
	Length uint8
	Value  []byte
}

type EapAkaPrimePkt struct {
	Subtype    uint8
	Attributes map[uint8]EapAkaPrimeAttribute
	MACInput   []byte
}

const (
	EAP_AKA_PRIME_TYPENUM = 50
)

// Attribute Types for EAP-AKA'
const (
	AT_RAND_ATTRIBUTE              = 1
	AT_AUTN_ATTRIBUTE              = 2
	AT_RES_ATTRIBUTE               = 3
	AT_AUTS_ATTRIBUTE              = 4
	AT_MAC_ATTRIBUTE               = 11
	AT_NOTIFICATION_ATTRIBUTE      = 12
	AT_IDENTITY_ATTRIBUTE          = 14
	AT_CLIENT_ERROR_CODE_ATTRIBUTE = 22
	AT_KDF_INPUT_ATTRIBUTE         = 23
	AT_KDF_ATTRIBUTE               = 24
)

// Subtypes for EAP-AKA'
const (
	AKA_CHALLENGE_SUBTYPE               = 1
	AKA_AUTHENTICATION_REJECT_SUBTYPE   = 2
	AKA_SYNCHRONIZATION_FAILURE_SUBTYPE = 4
	AKA_NOTIFICATION_SUBTYPE            = 12
	AKA_CLIENT_ERROR_SUBTYPE            = 14
)

var ausfContext AUSFContext

func Init() {
	if snRegex, err := regexp.Compile("5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org"); err != nil {
		logger.CtxLog.Warnf("SN compile error: %+v", err)
	} else {
		ausfContext.snRegex = snRegex
	}
	InitAusfContext(&ausfContext)
}

type NFContext interface {
	AuthorizationCheck(token string, serviceName models.Nrf_NFMgmt_ServiceName) error
}

var _ NFContext = &AUSFContext{}

func NewAusfUeContext(identifier string) (ausfUeContext *AusfUeContext) {
	ausfUeContext = new(AusfUeContext)
	ausfUeContext.Supi = identifier // supi
	return ausfUeContext
}

// AddAuthCtx stores an authentication that is not confirmed yet under its
// authCtxId, the SUCI or SUPI of the request that started it (TS 33.501
// clause 6.1.3.2), and replaces an earlier one under the same authCtxId. It
// first removes the authentications whose lifetime has passed.
func (c *AUSFContext) AddAuthCtx(authCtxId string, ue *AusfUeContext) {
	c.authCtxMu.Lock()
	defer c.authCtxMu.Unlock()
	t := now()
	for len(c.authCtxExpiries) > 0 && !t.Before(c.authCtxExpiries[0].ctx.expires) {
		e := c.authCtxExpiries[0]
		if c.authCtxs[e.authCtxId] == e.ctx {
			delete(c.authCtxs, e.authCtxId)
		}
		c.authCtxExpiries[0] = authCtxExpiry{}
		c.authCtxExpiries = c.authCtxExpiries[1:]
	}
	if c.authCtxs == nil {
		c.authCtxs = make(map[string]*authCtx)
	}
	ctx := &authCtx{ue: ue, expires: t.Add(authCtxLifetime)}
	c.authCtxs[authCtxId] = ctx
	c.authCtxExpiries = append(c.authCtxExpiries, authCtxExpiry{authCtxId: authCtxId, ctx: ctx})
}

// GetAuthCtx returns the authentication stored under authCtxId, unless it was
// confirmed or its lifetime has passed.
func (c *AUSFContext) GetAuthCtx(authCtxId string) (*AusfUeContext, bool) {
	c.authCtxMu.Lock()
	defer c.authCtxMu.Unlock()
	ctx, ok := c.authCtxs[authCtxId]
	if !ok || !now().Before(ctx.expires) {
		return nil, false
	}
	return ctx.ue, true
}

// ConfirmAuthCtx moves a successful authentication from its authCtxId to the
// confirmed context of its SUPI, which it replaces.
func (c *AUSFContext) ConfirmAuthCtx(authCtxId string, ue *AusfUeContext) {
	c.authCtxMu.Lock()
	if ctx, ok := c.authCtxs[authCtxId]; ok && ctx.ue == ue {
		delete(c.authCtxs, authCtxId)
	}
	c.authCtxMu.Unlock()
	ue.ConfirmedAt = time.Now()
	c.UePool.Store(ue.Supi, ue)
}

// RemoveUEAuthenticationContext removes the confirmed context of a SUPI and
// returns false if there was none. Deregister is addressed by SUPI, not by
// authCtxId; an authentication in progress is left to its lifetime, so that a
// late deregistration does not end a new registration.
func (c *AUSFContext) RemoveUEAuthenticationContext(supi string) bool {
	_, found := c.UePool.LoadAndDelete(supi)
	return found
}

// ReapStaleUeAuthContexts removes every confirmed AusfUeContext that has sat
// in UePool longer than ttl without an explicit TS 29.509 Deregister call -
// a crashed AMF or a UE that never properly detaches leaves one behind
// forever otherwise, since nothing else clears it. It returns the number of
// contexts reaped.
//
// Each stale entry is deleted with CompareAndDelete against the exact
// *AusfUeContext found during the scan, not a LoadAndDelete by key: the scan
// and the delete are two separate passes, so without this a SUPI that
// re-authenticates in between could have that fresh confirmation deleted
// instead of the stale one it replaced.
func (c *AUSFContext) ReapStaleUeAuthContexts(ttl time.Duration) int {
	now := time.Now()
	type staleEntry struct {
		key, value any
	}
	var stale []staleEntry
	c.UePool.Range(func(key, value any) bool {
		if ue, ok := value.(*AusfUeContext); ok && now.Sub(ue.ConfirmedAt) > ttl {
			stale = append(stale, staleEntry{key: key, value: value})
		}
		return true
	})

	reaped := 0
	for _, e := range stale {
		if c.UePool.CompareAndDelete(e.key, e.value) {
			reaped++
		}
	}
	return reaped
}

func IsServingNetworkAuthorized(lookup string) bool {
	if ausfContext.snRegex.MatchString(lookup) {
		return true
	} else {
		return false
	}
}

func GetSelf() *AUSFContext {
	return &ausfContext
}

func (a *AUSFContext) GetSelfID() string {
	return a.NfId
}

func (c *AUSFContext) GetTokenCtx(serviceName models.Nrf_NFMgmt_ServiceName, targetNF models.Nrf_NFMgmt_NFType) (
	context.Context, *models.ProblemDetails, error,
) {
	if !c.OAuth2Required {
		return context.TODO(), nil, nil
	}
	return oauth.GetTokenCtx(c.tokenRequest(serviceName, targetNF))
}

func (c *AUSFContext) GetTokenCtxForNFInstance(serviceName models.Nrf_NFMgmt_ServiceName,
	targetNF models.Nrf_NFMgmt_NFType, targetNFInstanceID string,
) (context.Context, *models.ProblemDetails, error) {
	if !c.OAuth2Required {
		return context.TODO(), nil, nil
	}
	targetID, err := uuid.Parse(strings.TrimSpace(targetNFInstanceID))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid target NF instance ID: %w", err)
	}
	if targetID.Version() != 4 {
		return nil, nil, errors.New("invalid target NF instance ID: UUID must be version 4")
	}
	return oauth.GetTokenCtx(c.tokenRequestForNFInstance(serviceName, targetNF, targetNFInstanceID))
}

func (c *AUSFContext) GetTokenCtxForNRF(serviceName models.Nrf_NFMgmt_ServiceName) (
	context.Context, *models.ProblemDetails, error,
) {
	return c.GetTokenCtxForNFInstance(serviceName, models.Nrf_NFMgmt_NFType_NRF, c.NrfNfInstanceID)
}

func (c *AUSFContext) tokenRequest(
	serviceName models.Nrf_NFMgmt_ServiceName,
	targetNF models.Nrf_NFMgmt_NFType,
) oauth.TokenRequest {
	return oauth.TokenRequest{
		ConsumerNFType:       models.Nrf_NFMgmt_NFType_AUSF,
		ConsumerNFInstanceID: c.NfId,
		TargetNFType:         targetNF,
		NRFURI:               c.NrfUri,
		Scope:                string(serviceName),
	}
}

func (c *AUSFContext) tokenRequestForNFInstance(serviceName models.Nrf_NFMgmt_ServiceName,
	targetNF models.Nrf_NFMgmt_NFType, targetNFInstanceID string,
) oauth.TokenRequest {
	request := c.tokenRequest(serviceName, targetNF)
	request.TargetNFInstanceID = targetNFInstanceID
	return request
}

func (c *AUSFContext) SetOAuth2Required(required bool) error {
	if !required {
		c.OAuth2Required = false
		c.NrfNfInstanceID = ""
		return nil
	}
	if strings.TrimSpace(c.NrfCertPem) == "" {
		return errors.New("OAuth2 enabled but NRF certificate path is empty")
	}
	if strings.TrimSpace(c.NrfUri) == "" {
		return errors.New("OAuth2 enabled but NRF URI is empty")
	}
	// Derive the expected NRF identity from the configured certificate.
	// Commit the new OAuth state only after identity parsing succeeds.
	nrfNfInstanceID, err := oauth.NFInstanceIDFromCertificate(c.NrfCertPem)
	if err != nil {
		return fmt.Errorf("derive trusted NRF instance ID from certificate: %w", err)
	}
	c.NrfNfInstanceID = nrfNfInstanceID
	c.OAuth2Required = true
	return nil
}

func (c *AUSFContext) AuthorizationCheck(token string, serviceName models.Nrf_NFMgmt_ServiceName) error {
	if !c.OAuth2Required {
		logger.UtilLog.Debugf("AUSFContext::AuthorizationCheck: OAuth2 not required\n")
		return nil
	}

	logger.UtilLog.Debugf("AUSFContext::AuthorizationCheck: tokenPresent[%t] serviceName[%s]",
		token != "", serviceName)
	// Use the certificate-derived NRF ID as the expected issuer.
	// Accept an audience matching either this AUSF instance or the AUSF type;
	// both accepted identities come from local state.
	return oauth.VerifyOAuth(token, string(serviceName), oauth.AudiencePolicy{
		NFInstanceID: c.NfId,
		NFType:       models.Nrf_NFMgmt_NFType_AUSF,
	}, c.NrfNfInstanceID, c.NrfCertPem)
}
