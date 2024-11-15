package processor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	ausf_authentication "github.com/ShouheiNishi/openapi5g/ausf/authentication"
	"github.com/ShouheiNishi/openapi5g/models"
	utils_error "github.com/ShouheiNishi/openapi5g/utils/error"
	"github.com/ShouheiNishi/openapi5g/utils/error/middleware"
	"github.com/bronze1man/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	strictgin "github.com/oapi-codegen/runtime/strictmiddleware/gin"
	"github.com/samber/lo"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/ausf/pkg/factory"
	"github.com/free5gc/util/ueauth"
)

func NewServerAusfAuthentication(processor *Processor) ausf_authentication.ServerInterface {
	return ausf_authentication.NewStrictHandler(
		&ausfAuthenticationStrictServer{
			processor: processor,
		},
		[]strictgin.StrictGinMiddlewareFunc{middleware.GinStrictServerMiddleware},
	)
}

type ausfAuthenticationStrictServer struct {
	processor *Processor
}

// (POST /rg-authentications)
func (s *ausfAuthenticationStrictServer) PostRgAuthentications(ctx context.Context,
	request ausf_authentication.PostRgAuthenticationsRequestObject) (
	ausf_authentication.PostRgAuthenticationsResponseObject, error,
) {
	return nil, errors.New("not implemented")
}

// (POST /ue-authentications/deregister)
func (s *ausfAuthenticationStrictServer) PostUeAuthenticationsDeregister(
	ctx context.Context, request ausf_authentication.PostUeAuthenticationsDeregisterRequestObject) (
	ausf_authentication.PostUeAuthenticationsDeregisterResponseObject, error,
) {
	return nil, errors.New("not implemented")
}

// Deletes the authentication result in the UDM
// (DELETE /ue-authentications/{authCtxId}/5g-aka-confirmation)
func (s *ausfAuthenticationStrictServer) Delete5gAkaAuthenticationResult(
	ctx context.Context, request ausf_authentication.Delete5gAkaAuthenticationResultRequestObject) (
	ausf_authentication.Delete5gAkaAuthenticationResultResponseObject, error,
) {
	return nil, errors.New("not implemented")
}

// Deletes the authentication result in the UDM
// (DELETE /ue-authentications/{authCtxId}/eap-session)
func (s *ausfAuthenticationStrictServer) DeleteEapAuthenticationResult(
	ctx context.Context, request ausf_authentication.DeleteEapAuthenticationResultRequestObject) (
	ausf_authentication.DeleteEapAuthenticationResultResponseObject, error,
) {
	return nil, errors.New("not implemented")
}

// (POST /ue-authentications/{authCtxId}/eap-session)
func (s *ausfAuthenticationStrictServer) EapAuthMethod(c context.Context,
	request ausf_authentication.EapAuthMethodRequestObject,
) (ausf_authentication.EapAuthMethodResponseObject, error) {
	logger.Auth5gAkaLog.Infof("EapAuthComfirmRequest")

	updateEapSession := request.Body
	eapSessionID := request.AuthCtxId

	var eapSession models.EapSession

	if !ausf_context.CheckIfSuciSupiPairExists(eapSessionID) {
		logger.AuthELog.Infoln("supiSuciPair does not exist, confirmation failed")
		problemDetails := models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  lo.ToPtr("USER_NOT_FOUND"),
		}
		return ausf_authentication.EapAuthMethoddefaultApplicationProblemPlusJSONResponse{
			StatusCode: problemDetails.Status,
			Body:       problemDetails,
		}, nil
	}

	currentSupi := ausf_context.GetSupiFromSuciSupiMap(eapSessionID)
	if !ausf_context.CheckIfAusfUeContextExists(currentSupi) {
		logger.AuthELog.Infoln("SUPI does not exist, confirmation failed")
		problemDetails := models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  lo.ToPtr("USER_NOT_FOUND"),
		}
		return ausf_authentication.EapAuthMethoddefaultApplicationProblemPlusJSONResponse{
			StatusCode: problemDetails.Status,
			Body:       problemDetails,
		}, nil
	}

	ausfCurrentContext := ausf_context.GetAusfUeContext(currentSupi)
	servingNetworkName := ausfCurrentContext.ServingNetworkName

	if ausfCurrentContext.AuthStatus == models.AUTHENTICATIONFAILURE {
		logger.AuthELog.Warnf("Authentication failed with status: %s", ausfCurrentContext.AuthStatus)
		eapFailPkt := ConstructEapNoTypePkt(radius.EapCodeFailure, 0)
		eapSession.EapPayload = &eapFailPkt
		eapSession.AuthResult = models.AUTHENTICATIONFAILURE
		return ausf_authentication.EapAuthMethod200JSONResponse(eapSession), nil
	}

	var eapPayload []byte
	if updateEapSession.EapPayload == nil {
		logger.AuthELog.Warnf("EAP Payload is not exist")
	} else if eapPayloadTmp, err := base64.StdEncoding.DecodeString(*updateEapSession.EapPayload); err != nil {
		logger.AuthELog.Warnf("EAP Payload decode failed: %+v", err)
	} else {
		eapPayload = eapPayloadTmp
	}

	eapGoPkt := gopacket.NewPacket(eapPayload, layers.LayerTypeEAP, gopacket.Default)
	eapLayer := eapGoPkt.Layer(layers.LayerTypeEAP)
	eapContent, _ := eapLayer.(*layers.EAP)
	eapOK := true
	var eapErrStr string

	if eapContent.Code != layers.EAPCodeResponse {
		eapOK = false
		eapErrStr = "eap packet code error"
	} else if eapContent.Type != ausf_context.EAP_AKA_PRIME_TYPENUM {
		eapOK = false
		eapErrStr = "eap packet type error"
	} else if decodeEapAkaPrimePkt, err := decodeEapAkaPrime(eapContent.Contents); err != nil {
		logger.AuthELog.Warnf("EAP-AKA' decode failed: %+v", err)
		eapOK = false
		eapErrStr = "eap packet error"
	} else {
		switch decodeEapAkaPrimePkt.Subtype {
		case ausf_context.AKA_CHALLENGE_SUBTYPE:
			K_autStr := ausfCurrentContext.K_aut
			var K_aut []byte
			if K_autTmp, err := hex.DecodeString(K_autStr); err != nil {
				logger.AuthELog.Warnf("K_aut decode error: %+v", err)
			} else {
				K_aut = K_autTmp
			}
			XMAC := CalculateAtMAC(K_aut, decodeEapAkaPrimePkt.MACInput)
			MAC := decodeEapAkaPrimePkt.Attributes[ausf_context.AT_MAC_ATTRIBUTE].Value
			XRES := ausfCurrentContext.XRES
			RES := hex.EncodeToString(decodeEapAkaPrimePkt.Attributes[ausf_context.AT_RES_ATTRIBUTE].Value)

			if !bytes.Equal(MAC, XMAC) {
				eapOK = false
				eapErrStr = "EAP-AKA' integrity check fail"
			} else if XRES == RES {
				logger.AuthELog.Infoln("Correct RES value, EAP-AKA' auth succeed")
				eapSession.KSeaf = ausfCurrentContext.Kseaf
				eapSession.Supi = currentSupi
				eapSession.AuthResult = models.AUTHENTICATIONSUCCESS
				eapSuccPkt := ConstructEapNoTypePkt(radius.EapCodeSuccess, eapContent.Id)
				eapSession.EapPayload = &eapSuccPkt
				udmUrl := ausfCurrentContext.UdmUeauUrl
				if sendErr := s.processor.Consumer().SendAuthResultToUDM(
					eapSessionID,
					models.AuthTypeEAPAKAPRIME,
					true,
					servingNetworkName,
					udmUrl); sendErr != nil {
					logger.AuthELog.Infoln(sendErr.Error())
					problemDetails := models.ProblemDetails{
						Status: http.StatusInternalServerError,
						Cause:  lo.ToPtr("UPSTREAM_SERVER_ERROR"),
					}
					return ausf_authentication.EapAuthMethoddefaultApplicationProblemPlusJSONResponse{
						StatusCode: problemDetails.Status,
						Body:       problemDetails,
					}, nil
				}
				ausfCurrentContext.AuthStatus = models.AUTHENTICATIONSUCCESS
			} else {
				eapOK = false
				eapErrStr = "Wrong RES value, EAP-AKA' auth failed"
			}
		case ausf_context.AKA_AUTHENTICATION_REJECT_SUBTYPE:
			ausfCurrentContext.AuthStatus = models.AUTHENTICATIONFAILURE
		case ausf_context.AKA_SYNCHRONIZATION_FAILURE_SUBTYPE:
			logger.AuthELog.Warnf("EAP-AKA' synchronziation failure")
			if ausfCurrentContext.Resynced {
				eapOK = false
				eapErrStr = "2 consecutive Synch Failure, terminate authentication procedure"
			} else {
				var authInfo models.AuthenticationInfo
				AUTS := decodeEapAkaPrimePkt.Attributes[ausf_context.AT_AUTS_ATTRIBUTE].Value
				resynchronizationInfo := &models.ResynchronizationInfo{
					Auts: hex.EncodeToString(AUTS[:]),
				}
				authInfo.SupiOrSuci = eapSessionID
				authInfo.ServingNetworkName = servingNetworkName
				authInfo.ResynchronizationInfo = resynchronizationInfo
				response, _, problemDetails := s.processor.UeAuthPostRequestProcedure(c, authInfo)
				if problemDetails != nil {
					return ausf_authentication.EapAuthMethoddefaultApplicationProblemPlusJSONResponse{
						StatusCode: problemDetails.Status,
						Body:       *problemDetails,
					}, nil
				}
				ausfCurrentContext.Resynced = true
				eapPayload, err := response.N5gAuthData.AsEapPayload()
				if err != nil {
					return nil, err
				}
				eapSession.EapPayload = &eapPayload
				eapSession.Links = &response.Links
				eapSession.AuthResult = models.AUTHENTICATIONONGOING
			}
		case ausf_context.AKA_NOTIFICATION_SUBTYPE:
			ausfCurrentContext.AuthStatus = models.AUTHENTICATIONFAILURE
		case ausf_context.AKA_CLIENT_ERROR_SUBTYPE:
			logger.AuthELog.Warnf("EAP-AKA' failure: receive client-error")
			ausfCurrentContext.AuthStatus = models.AUTHENTICATIONFAILURE
		default:
			ausfCurrentContext.AuthStatus = models.AUTHENTICATIONFAILURE
		}
	}

	if !eapOK {
		logger.AuthELog.Warnf("EAP-AKA' failure: %s", eapErrStr)
		if sendErr := s.processor.Consumer().SendAuthResultToUDM(eapSessionID, models.AuthTypeEAPAKAPRIME, false,
			servingNetworkName, ausfCurrentContext.UdmUeauUrl); sendErr != nil {
			logger.AuthELog.Infoln(sendErr.Error())
			problemDetails := models.ProblemDetails{
				Status: http.StatusInternalServerError,
				Cause:  lo.ToPtr("UPSTREAM_SERVER_ERROR"),
			}
			return ausf_authentication.EapAuthMethoddefaultApplicationProblemPlusJSONResponse{
				StatusCode: problemDetails.Status,
				Body:       problemDetails,
			}, nil
		}

		ausfCurrentContext.AuthStatus = models.AUTHENTICATIONFAILURE
		eapSession.AuthResult = models.AUTHENTICATIONONGOING
		failEapAkaNoti := ConstructFailEapAkaNotification(eapContent.Id)
		eapSession.EapPayload = &failEapAkaNoti
		self := ausf_context.GetSelf()
		linkUrl := self.Url + factory.AusfAuthResUriPrefix + "/ue-authentications/" + eapSessionID + "/eap-session"
		var linksValue models.LinksValueSchema
		if err := linksValue.FromLink(models.Link{Href: &linkUrl}); err != nil {
			problemDetails := utils_error.ErrorToProblemDetails(err)
			return ausf_authentication.EapAuthMethoddefaultApplicationProblemPlusJSONResponse{
				StatusCode: problemDetails.Status,
				Body:       problemDetails,
			}, nil
		}
		eapSession.Links = &map[string]models.LinksValueSchema{}
		(*eapSession.Links)["eap-session"] = linksValue
	} else if ausfCurrentContext.AuthStatus == models.AUTHENTICATIONFAILURE {
		if sendErr := s.processor.Consumer().SendAuthResultToUDM(eapSessionID, models.AuthTypeEAPAKAPRIME, false,
			servingNetworkName, ausfCurrentContext.UdmUeauUrl); sendErr != nil {
			logger.AuthELog.Infoln(sendErr.Error())
			var problemDetails models.ProblemDetails
			problemDetails.Status = http.StatusInternalServerError
			problemDetails.Cause = lo.ToPtr("UPSTREAM_SERVER_ERROR")
		}

		eapFailPkt := ConstructEapNoTypePkt(radius.EapCodeFailure, eapPayload[1])
		eapSession.EapPayload = &eapFailPkt
		eapSession.AuthResult = models.AUTHENTICATIONFAILURE
	}

	return ausf_authentication.EapAuthMethod200JSONResponse(eapSession), nil
}

// (POST /ue-authentications)
func (s *ausfAuthenticationStrictServer) PostUeAuthentications(ctx context.Context,
	request ausf_authentication.PostUeAuthenticationsRequestObject) (
	ausf_authentication.PostUeAuthenticationsResponseObject, error,
) {
	logger.UeAuthLog.Infof("HandleUeAuthPostRequest")

	if request.Body == nil {
		return ausf_authentication.PostUeAuthentications400ApplicationProblemPlusJSONResponse{
			Cause:  lo.ToPtr("BODY_NOT_EXIST"),
			Status: http.StatusBadRequest,
		}, nil
	}

	updateAuthenticationInfo := *request.Body

	response, locationURI, problemDetails := s.processor.UeAuthPostRequestProcedure(ctx, updateAuthenticationInfo)

	if response != nil {
		return ausf_authentication.PostUeAuthentications201Application3gppHalPlusJSONResponse{
			Body: *response,
			Headers: ausf_authentication.PostUeAuthentications201ResponseHeaders{
				Location: locationURI,
			},
		}, nil
	} else if problemDetails != nil {
		return ausf_authentication.PostUeAuthenticationsdefaultApplicationProblemPlusJSONResponse{
			StatusCode: problemDetails.Status,
			Body:       *problemDetails,
		}, nil
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  lo.ToPtr("UNSPECIFIED"),
	}
	return ausf_authentication.PostUeAuthentications403ApplicationProblemPlusJSONResponse(*problemDetails), nil
}

func (p *Processor) UeAuthPostRequestProcedure(c context.Context, updateAuthenticationInfo models.AuthenticationInfo,
) (*models.UEAuthenticationCtx, string, *models.ProblemDetails) {
	var responseBody models.UEAuthenticationCtx
	var authInfoReq models.AuthenticationInfoRequest

	supiOrSuci := updateAuthenticationInfo.SupiOrSuci

	snName := updateAuthenticationInfo.ServingNetworkName
	servingNetworkAuthorized := ausf_context.IsServingNetworkAuthorized(snName)
	if !servingNetworkAuthorized {
		problemDetails := models.ProblemDetails{
			Cause:  lo.ToPtr("SERVING_NETWORK_NOT_AUTHORIZED"),
			Status: http.StatusForbidden,
		}
		logger.UeAuthLog.Infoln("403 forbidden: serving network NOT AUTHORIZED")
		return nil, "", &problemDetails
	}
	logger.UeAuthLog.Infoln("Serving network authorized")

	responseBody.ServingNetworkName = snName
	authInfoReq.ServingNetworkName = snName
	self := ausf_context.GetSelf()
	authInfoReq.AusfInstanceId = self.GetSelfID()

	var lastEapID uint8
	if updateAuthenticationInfo.ResynchronizationInfo != nil {
		logger.UeAuthLog.Warningln("Auts: ", updateAuthenticationInfo.ResynchronizationInfo.Auts)
		ausfCurrentSupi := ausf_context.GetSupiFromSuciSupiMap(supiOrSuci)
		logger.UeAuthLog.Warningln(ausfCurrentSupi)
		ausfCurrentContext := ausf_context.GetAusfUeContext(ausfCurrentSupi)
		logger.UeAuthLog.Warningln(ausfCurrentContext.Rand)
		if updateAuthenticationInfo.ResynchronizationInfo.Rand == "" {
			updateAuthenticationInfo.ResynchronizationInfo.Rand = ausfCurrentContext.Rand
		}
		logger.UeAuthLog.Warningln("Rand: ", updateAuthenticationInfo.ResynchronizationInfo.Rand)
		authInfoReq.ResynchronizationInfo = updateAuthenticationInfo.ResynchronizationInfo
		lastEapID = ausfCurrentContext.EapID
	}

	udmUrl := p.Consumer().GetUdmUrl(self.NrfUri)

	result, err, pd := p.Consumer().GenerateAuthDataApi(udmUrl, supiOrSuci, authInfoReq)
	if err != nil {
		if pd == nil {
			pd = lo.ToPtr(utils_error.ErrorToProblemDetails(err))
		}
		logger.UeAuthLog.Infof("GenerateAuthDataApi error: %+v", err)
		return nil, "", pd
	}
	authInfoResult := *result

	ueid := authInfoResult.Supi
	ausfUeContext := ausf_context.NewAusfUeContext(ueid)
	ausfUeContext.ServingNetworkName = snName
	ausfUeContext.AuthStatus = models.AUTHENTICATIONONGOING
	ausfUeContext.UdmUeauUrl = udmUrl
	ausf_context.AddAusfUeContextToPool(ausfUeContext)

	logger.UeAuthLog.Infof("Add SuciSupiPair (%s, %s) to map.\n", supiOrSuci, ueid)
	ausf_context.AddSuciSupiPairToMap(supiOrSuci, ueid)

	locationURI := self.Url + factory.AusfAuthResUriPrefix + "/ue-authentications/" + supiOrSuci
	putLink := locationURI
	if authInfoResult.AuthType == models.AuthTypeN5GAKA {
		logger.UeAuthLog.Infoln("Use 5G AKA auth method")
		putLink += "/5g-aka-confirmation"

		var av5GHeAka models.Av5GHeAka
		if av5GHeAka_tmp, err := authInfoResult.AuthenticationVector.AsAv5GHeAka(); err != nil {
			problemDetails := &models.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: http.StatusInternalServerError,
			}
			logger.UeAuthLog.Infoln("500 internal server error: UDM client fail")
			return nil, "", problemDetails
		} else {
			av5GHeAka = av5GHeAka_tmp
		}

		// Derive HXRES* from XRES*
		concat := av5GHeAka.Rand + av5GHeAka.XresStar
		var hxresStarBytes []byte
		if bytes, err := hex.DecodeString(concat); err != nil {
			logger.Auth5gAkaLog.Errorf("decode concat error: %+v", err)
			problemDetails := models.ProblemDetails{
				Title:  lo.ToPtr("Concat Decode Problem"),
				Cause:  lo.ToPtr("CONCAT_DECODE_PROBLEM"),
				Detail: lo.ToPtr(err.Error()),
				Status: http.StatusInternalServerError,
			}
			return nil, "", &problemDetails
		} else {
			hxresStarBytes = bytes
		}
		hxresStarAll := sha256.Sum256(hxresStarBytes)
		hxresStar := hex.EncodeToString(hxresStarAll[16:]) // last 128 bits
		logger.Auth5gAkaLog.Infof("XresStar = %x\n", av5GHeAka.XresStar)

		// Derive Kseaf from Kausf
		Kausf := av5GHeAka.Kausf
		var KausfDecode []byte
		if ausfDecode, err := hex.DecodeString(Kausf); err != nil {
			logger.Auth5gAkaLog.Errorf("decode Kausf failed: %+v", err)
			problemDetails := models.ProblemDetails{
				Title:  lo.ToPtr("Kausf Decode Problem"),
				Cause:  lo.ToPtr("KAUSF_DECODE_PROBLEM"),
				Detail: lo.ToPtr(err.Error()),
				Status: http.StatusInternalServerError,
			}
			return nil, "", &problemDetails
		} else {
			KausfDecode = ausfDecode
		}
		P0 := []byte(snName)
		Kseaf, err := ueauth.GetKDFValue(KausfDecode, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))
		if err != nil {
			logger.Auth5gAkaLog.Errorf("GetKDFValue failed: %+v", err)
			problemDetails := models.ProblemDetails{
				Title:  lo.ToPtr("Kseaf Derivation Problem"),
				Cause:  lo.ToPtr("KSEAF_DERIVATION_PROBLEM"),
				Detail: lo.ToPtr(err.Error()),
				Status: http.StatusInternalServerError,
			}
			return nil, "", &problemDetails
		}
		ausfUeContext.XresStar = av5GHeAka.XresStar
		ausfUeContext.Kausf = Kausf
		ausfUeContext.Kseaf = hex.EncodeToString(Kseaf)
		ausfUeContext.Rand = av5GHeAka.Rand

		var av5gAka models.Av5gAka
		av5gAka.Rand = av5GHeAka.Rand
		av5gAka.Autn = av5GHeAka.Autn
		av5gAka.HxresStar = hxresStar
		if err := responseBody.N5gAuthData.FromAv5gAka(av5gAka); err != nil {
			problemDetails := &models.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: http.StatusInternalServerError,
			}
			logger.UeAuthLog.Infoln("500 internal server error: UDM client fail")
			return nil, "", problemDetails
		}

		var linksValue models.LinksValueSchema
		if err := linksValue.FromLink(models.Link{Href: &putLink}); err != nil {
			problemDetails := &models.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: http.StatusInternalServerError,
			}
			logger.UeAuthLog.Infoln("500 internal server error: UDM client fail")
			return nil, "", problemDetails
		}
		responseBody.Links = make(map[string]models.LinksValueSchema)
		responseBody.Links["5g-aka"] = linksValue
	} else if authInfoResult.AuthType == models.AuthTypeEAPAKAPRIME {
		logger.UeAuthLog.Infoln("Use EAP-AKA' auth method")
		putLink += "/eap-session"

		avEapAkaPrime, err := authInfoResult.AuthenticationVector.AsAvEapAkaPrime()
		if err != nil {
			problemDetails := &models.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: http.StatusInternalServerError,
			}
			logger.UeAuthLog.Infoln("500 internal server error: UDM client fail")
			return nil, "", problemDetails
		}

		var identity string
		// TODO support more SUPI type
		if ueid[:4] == "imsi" {
			if !self.EapAkaSupiImsiPrefix {
				// 33.501 v15.9.0 or later
				identity = ueid[5:]
			} else {
				// 33.501 v15.8.0 or earlier
				identity = ueid
			}
		}
		ikPrime := avEapAkaPrime.IkPrime
		ckPrime := avEapAkaPrime.CkPrime
		RAND := avEapAkaPrime.Rand
		AUTN := avEapAkaPrime.Autn
		XRES := avEapAkaPrime.Xres
		ausfUeContext.XRES = XRES

		ausfUeContext.Rand = avEapAkaPrime.Rand

		_, K_aut, _, _, EMSK := eapAkaPrimePrf(ikPrime, ckPrime, identity)
		logger.AuthELog.Tracef("K_aut: %x", K_aut)
		ausfUeContext.K_aut = hex.EncodeToString(K_aut)
		Kausf := EMSK[0:32]
		ausfUeContext.Kausf = hex.EncodeToString(Kausf)
		P0 := []byte(snName)
		Kseaf, err := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))
		if err != nil {
			logger.AuthELog.Errorf("GetKDFValue failed: %+v", err)
		}
		ausfUeContext.Kseaf = hex.EncodeToString(Kseaf)

		var eapPkt radius.EapPacket
		eapPkt.Code = radius.EapCode(1)
		if updateAuthenticationInfo.ResynchronizationInfo == nil {
			src := rand.NewSource(time.Now().UnixNano())
			r := rand.New(src)
			randIdentifier := r.Intn(256)
			ausfUeContext.EapID = uint8(randIdentifier)
		} else {
			ausfUeContext.EapID = lastEapID + 1
		}
		eapPkt.Identifier = ausfUeContext.EapID
		eapPkt.Type = radius.EapType(50) // according to RFC5448 6.1

		var eapAKAHdr, atRand, atAutn, atKdf, atKdfInput, atMAC string
		eapAKAHdrBytes := make([]byte, 3) // RFC4187 8.1
		eapAKAHdrBytes[0] = ausf_context.AKA_CHALLENGE_SUBTYPE
		eapAKAHdr = string(eapAKAHdrBytes)
		if atRandTmp, err := EapEncodeAttribute("AT_RAND", RAND); err != nil {
			logger.AuthELog.Errorf("EAP encode RAND failed: %+v", err)
		} else {
			atRand = atRandTmp
		}
		if atAutnTmp, err := EapEncodeAttribute("AT_AUTN", AUTN); err != nil {
			logger.AuthELog.Errorf("EAP encode AUTN failed: %+v", err)
		} else {
			atAutn = atAutnTmp
		}
		if atKdfTmp, err := EapEncodeAttribute("AT_KDF", snName); err != nil {
			logger.AuthELog.Errorf("EAP encode KDF failed: %+v", err)
		} else {
			atKdf = atKdfTmp
		}
		if atKdfInputTmp, err := EapEncodeAttribute("AT_KDF_INPUT", snName); err != nil {
			logger.AuthELog.Errorf("EAP encode KDF failed: %+v", err)
		} else {
			atKdfInput = atKdfInputTmp
		}
		if atMACTmp, err := EapEncodeAttribute("AT_MAC", ""); err != nil {
			logger.AuthELog.Errorf("EAP encode MAC failed: %+v", err)
		} else {
			atMAC = atMACTmp
		}

		dataArrayBeforeMAC := eapAKAHdr + atRand + atAutn + atKdf + atKdfInput + atMAC
		eapPkt.Data = []byte(dataArrayBeforeMAC)
		encodedPktBeforeMAC := eapPkt.Encode()

		MacValue := CalculateAtMAC(K_aut, encodedPktBeforeMAC)
		atMAC = atMAC[:4] + string(MacValue)

		dataArrayAfterMAC := eapAKAHdr + atRand + atAutn + atKdf + atKdfInput + atMAC

		eapPkt.Data = []byte(dataArrayAfterMAC)
		encodedPktAfterMAC := eapPkt.Encode()
		if err := responseBody.N5gAuthData.FromEapPayload(
			base64.StdEncoding.EncodeToString(encodedPktAfterMAC)); err != nil {
			problemDetails := &models.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: http.StatusInternalServerError,
			}
			logger.UeAuthLog.Infoln("500 internal server error: UDM client fail")
			return nil, "", problemDetails
		}

		var linksValue models.LinksValueSchema
		if err := linksValue.FromLink(models.Link{Href: &putLink}); err != nil {
			problemDetails := &models.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: http.StatusInternalServerError,
			}
			logger.UeAuthLog.Infoln("500 internal server error: UDM client fail")
			return nil, "", problemDetails
		}
		responseBody.Links = make(map[string]models.LinksValueSchema)
		responseBody.Links["eap-session"] = linksValue
	}

	responseBody.AuthType = models.AusfAuthType(authInfoResult.AuthType)

	return &responseBody, locationURI, nil
}

// (PUT /ue-authentications/{authCtxId}/5g-aka-confirmation)
func (s *ausfAuthenticationStrictServer) PutUeAuthenticationsAuthCtxId5gAkaConfirmation(ctx context.Context,
	request ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmationRequestObject) (
	ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmationResponseObject, error,
) {
	logger.Auth5gAkaLog.Infof("Auth5gAkaComfirmRequest")

	updateConfirmationData := request.Body
	ConfirmationDataResponseID := request.AuthCtxId

	var confirmDataRsp models.ConfirmationDataResponse
	success := false
	confirmDataRsp.AuthResult = models.AUTHENTICATIONFAILURE

	if !ausf_context.CheckIfSuciSupiPairExists(ConfirmationDataResponseID) {
		logger.Auth5gAkaLog.Infof("supiSuciPair does not exist, confirmation failed (queried by %s)\n",
			ConfirmationDataResponseID)
		problemDetails := models.ProblemDetails{
			Cause:  lo.ToPtr("USER_NOT_FOUND"),
			Status: http.StatusBadRequest,
		}
		return ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmationdefaultApplicationProblemPlusJSONResponse{
			StatusCode: problemDetails.Status,
			Body:       problemDetails,
		}, nil
	}

	currentSupi := ausf_context.GetSupiFromSuciSupiMap(ConfirmationDataResponseID)
	if !ausf_context.CheckIfAusfUeContextExists(currentSupi) {
		logger.Auth5gAkaLog.Infof("SUPI does not exist, confirmation failed (queried by %s)\n", currentSupi)
		problemDetails := models.ProblemDetails{
			Cause:  lo.ToPtr("USER_NOT_FOUND"),
			Status: http.StatusBadRequest,
		}
		return ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmationdefaultApplicationProblemPlusJSONResponse{
			StatusCode: problemDetails.Status,
			Body:       problemDetails,
		}, nil
	}

	ausfCurrentContext := ausf_context.GetAusfUeContext(currentSupi)
	servingNetworkName := ausfCurrentContext.ServingNetworkName

	// Compare the received RES* with the stored XRES*
	logger.Auth5gAkaLog.Infof("res*: %x\nXres*: %x\n", updateConfirmationData.ResStar, ausfCurrentContext.XresStar)
	if updateConfirmationData.ResStar != nil &&
		strings.EqualFold(*updateConfirmationData.ResStar, ausfCurrentContext.XresStar) {
		ausfCurrentContext.AuthStatus = models.AUTHENTICATIONSUCCESS
		confirmDataRsp.AuthResult = models.AUTHENTICATIONSUCCESS
		success = true
		logger.Auth5gAkaLog.Infoln("5G AKA confirmation succeeded")
		confirmDataRsp.Supi = currentSupi
		confirmDataRsp.Kseaf = ausfCurrentContext.Kseaf
	} else {
		ausfCurrentContext.AuthStatus = models.AUTHENTICATIONFAILURE
		confirmDataRsp.AuthResult = models.AUTHENTICATIONFAILURE
		s.processor.logConfirmFailureAndInformUDM(ConfirmationDataResponseID, models.AuthTypeN5GAKA, servingNetworkName,
			"5G AKA confirmation failed", ausfCurrentContext.UdmUeauUrl)
	}

	if sendErr := s.processor.Consumer().SendAuthResultToUDM(currentSupi, models.AuthTypeN5GAKA, success,
		servingNetworkName, ausfCurrentContext.UdmUeauUrl); sendErr != nil {
		logger.Auth5gAkaLog.Infoln(sendErr.Error())
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  lo.ToPtr("UPSTREAM_SERVER_ERROR"),
		}
		return ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmationdefaultApplicationProblemPlusJSONResponse{
			StatusCode: problemDetails.Status,
			Body:       problemDetails,
		}, nil
	}

	return ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmation200JSONResponse(confirmDataRsp), nil
}

func KDF5gAka(param ...string) hash.Hash {
	s := param[0]
	s += param[1]
	if p0len, err := strconv.Atoi(param[2]); err != nil {
		logger.AuthELog.Warnf("atoi failed: %+v", err)
	} else {
		s += strconv.FormatInt(int64(p0len), 16)
	}
	h := hmac.New(sha256.New, []byte(s))

	return h
}

func intToByteArray(i int) []byte {
	r := make([]byte, 2)
	binary.BigEndian.PutUint16(r, uint16(i))
	return r
}

func padZeros(byteArray []byte, size int) []byte {
	l := len(byteArray)
	if l == size {
		return byteArray
	}
	r := make([]byte, size)
	copy(r[size-l:], byteArray)
	return r
}

func CalculateAtMAC(key []byte, input []byte) []byte {
	// keyed with K_aut
	h := hmac.New(sha256.New, key)
	if _, err := h.Write(input); err != nil {
		logger.AuthELog.Errorln(err.Error())
	}
	sum := h.Sum(nil)
	return sum[:16]
}

func EapEncodeAttribute(attributeType string, data string) (string, error) {
	var attribute string
	var length int

	switch attributeType {
	case "AT_RAND":
		length = len(data)/8 + 1
		if length != 5 {
			return "", fmt.Errorf("[eapEncodeAttribute] AT_RAND Length Error")
		}
		attrNum := fmt.Sprintf("%02x", ausf_context.AT_RAND_ATTRIBUTE)
		attribute = attrNum + "05" + "0000" + data

	case "AT_AUTN":
		length = len(data)/8 + 1
		if length != 5 {
			return "", fmt.Errorf("[eapEncodeAttribute] AT_AUTN Length Error")
		}
		attrNum := fmt.Sprintf("%02x", ausf_context.AT_AUTN_ATTRIBUTE)
		attribute = attrNum + "05" + "0000" + data

	case "AT_KDF_INPUT":
		var byteName []byte
		nLength := len(data)
		length := (nLength+3)/4 + 1
		b := make([]byte, length*4)
		byteNameLength := intToByteArray(nLength)
		byteName = []byte(data)
		pad := padZeros(byteName, (length-1)*4)
		b[0] = 23
		b[1] = byte(length)
		copy(b[2:4], byteNameLength)
		copy(b[4:], pad)
		return string(b[:]), nil

	case "AT_KDF":
		// Value 1 default key derivation function for EAP-AKA'
		attrNum := fmt.Sprintf("%02x", ausf_context.AT_KDF_ATTRIBUTE)
		attribute = attrNum + "01" + "0001"

	case "AT_MAC":
		// Pad MAC value with 16 bytes of 0 since this is just for the calculation of MAC
		attrNum := fmt.Sprintf("%02x", ausf_context.AT_MAC_ATTRIBUTE)
		attribute = attrNum + "05" + "0000" + "00000000000000000000000000000000"

	case "AT_RES":
		var byteName []byte
		nLength := len(data)
		length := (nLength+3)/4 + 1
		b := make([]byte, length*4)
		byteNameLength := intToByteArray(nLength)
		byteName = []byte(data)
		pad := padZeros(byteName, (length-1)*4)
		b[0] = 3
		b[1] = byte(length)
		copy(b[2:4], byteNameLength)
		copy(b[4:], pad)
		return string(b[:]), nil

	default:
		logger.AuthELog.Errorf("UNKNOWN attributeType %s\n", attributeType)
		return "", nil
	}

	if r, err := hex.DecodeString(attribute); err != nil {
		return "", err
	} else {
		return string(r), nil
	}
}

func eapAkaPrimePrf(ikPrime string, ckPrime string, identity string) ([]byte, []byte, []byte, []byte, []byte) {
	keyAp := ikPrime + ckPrime

	var key []byte
	if keyTmp, err := hex.DecodeString(keyAp); err != nil {
		logger.AuthELog.Warnf("Decode key AP failed: %+v", err)
	} else {
		key = keyTmp
	}
	sBase := []byte("EAP-AKA'" + identity)

	MK := []byte("")
	prev := []byte("")
	prfRounds := 208/32 + 1
	for i := 0; i < prfRounds; i++ {
		// Create a new HMAC by defining the hash type and the key (as byte array)
		h := hmac.New(sha256.New, key)

		hexNum := (byte)(i + 1)
		ap := append(sBase, hexNum)
		s := append(prev, ap...)

		// Write Data to it
		if _, err := h.Write(s); err != nil {
			logger.AuthELog.Errorln(err.Error())
		}

		// Get result
		sha := h.Sum(nil)
		MK = append(MK, sha...)
		prev = sha
	}

	K_encr := MK[0:16]  // 0..127
	K_aut := MK[16:48]  // 128..383
	K_re := MK[48:80]   // 384..639
	MSK := MK[80:144]   // 640..1151
	EMSK := MK[144:208] // 1152..1663
	return K_encr, K_aut, K_re, MSK, EMSK
}

func decodeEapAkaPrime(eapPkt []byte) (*ausf_context.EapAkaPrimePkt, error) {
	var decodePkt ausf_context.EapAkaPrimePkt
	var attrLen int
	var decodeAttr ausf_context.EapAkaPrimeAttribute
	attributes := make(map[uint8]ausf_context.EapAkaPrimeAttribute)
	data := eapPkt[5:]
	decodePkt.Subtype = data[0]
	dataLen := len(data)

	// decode attributes
	for i := 3; i < dataLen; i += attrLen {
		attrType := data[i]
		attrLen = int(data[i+1]) * 4
		if attrLen == 0 {
			return nil, fmt.Errorf("attribute length equal to zero")
		}
		if i+attrLen > dataLen {
			return nil, fmt.Errorf("packet length out of range")
		}
		switch attrType {
		case ausf_context.AT_RES_ATTRIBUTE:
			logger.AuthELog.Tracef("Decoding AT_RES\n")
			accLen := int(data[i+3] >> 3)
			if accLen > 16 || accLen < 4 || accLen+4 > attrLen {
				return nil, fmt.Errorf("attribute AT_RES decode err")
			}

			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			decodeAttr.Value = data[i+4 : i+4+accLen]
			attributes[attrType] = decodeAttr
		case ausf_context.AT_MAC_ATTRIBUTE:
			logger.AuthELog.Tracef("Decoding AT_MAC\n")
			if attrLen != 20 {
				return nil, fmt.Errorf("attribute AT_MAC decode err")
			}
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			Mac := make([]byte, attrLen-4)
			copy(Mac, data[i+4:i+attrLen])
			decodeAttr.Value = Mac
			attributes[attrType] = decodeAttr

			// clean AT_MAC value for integrity check later
			zeros := make([]byte, attrLen-4)
			copy(data[i+4:i+attrLen], zeros)
			decodePkt.MACInput = eapPkt
		case ausf_context.AT_KDF_ATTRIBUTE:
			logger.AuthELog.Tracef("Decoding AT_KDF\n")
			if attrLen != 4 {
				return nil, fmt.Errorf("attribute AT_KDF decode err")
			}
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			decodeAttr.Value = data[i+2 : i+attrLen]
			attributes[attrType] = decodeAttr
		case ausf_context.AT_AUTS_ATTRIBUTE:
			logger.AuthELog.Tracef("Decoding AT_AUTS\n")
			if attrLen != 16 {
				return nil, fmt.Errorf("attribute AT_AUTS decode err")
			}
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			decodeAttr.Value = data[i+2 : i+attrLen]
			attributes[attrType] = decodeAttr
		case ausf_context.AT_CLIENT_ERROR_CODE_ATTRIBUTE:
			logger.AuthELog.Tracef("Decoding AT_CLIENT_ERROR_CODE\n")
			if attrLen != 4 {
				return nil, fmt.Errorf("attribute AT_CLIENT_ERROR_CODE decode err")
			}
			decodeAttr.Type = attrType
			decodeAttr.Length = data[i+1]
			decodeAttr.Value = data[i+2 : i+attrLen]
			attributes[attrType] = decodeAttr
		default:
			logger.AuthELog.Tracef("attribute type %x skipped\n", attrType)
		}
	}

	switch decodePkt.Subtype {
	case ausf_context.AKA_CHALLENGE_SUBTYPE:
		logger.AuthELog.Tracef("Subtype AKA-Challenge\n")
		if _, ok := attributes[ausf_context.AT_RES_ATTRIBUTE]; !ok {
			return nil, fmt.Errorf("AKA-Challenge attributes error")
		} else if _, ok := attributes[ausf_context.AT_MAC_ATTRIBUTE]; !ok {
			return nil, fmt.Errorf("AKA-Challenge attributes error")
		}
	case ausf_context.AKA_AUTHENTICATION_REJECT_SUBTYPE:
		logger.AuthELog.Tracef("Subtype AKA-Authentication-Reject\n")
		if len(attributes) != 0 {
			return nil, fmt.Errorf("AKA-Authentication-Reject attributes error")
		}
	case ausf_context.AKA_SYNCHRONIZATION_FAILURE_SUBTYPE:
		logger.AuthELog.Tracef("Subtype AKA-Synchronization-Failure\n")
		if len(attributes) != 2 {
			return nil, fmt.Errorf("AKA-Synchornization-Failure attributes error")
		} else if _, ok := attributes[ausf_context.AT_AUTS_ATTRIBUTE]; !ok {
			return nil, fmt.Errorf("AKA-Synchornization-Failure attributes error")
		} else if _, ok := attributes[ausf_context.AT_KDF_ATTRIBUTE]; !ok {
			return nil, fmt.Errorf("AKA-Synchornization-Failure attributes error")
		} else if kdfVal := attributes[ausf_context.AT_KDF_ATTRIBUTE].Value; !(kdfVal[0] == 0 && kdfVal[1] == 1) {
			return nil, fmt.Errorf("AKA-Synchornization-Failure attributes error")
		}
	case ausf_context.AKA_NOTIFICATION_SUBTYPE:
		logger.AuthELog.Tracef("Subtype AKA-Notification\n")
	case ausf_context.AKA_CLIENT_ERROR_SUBTYPE:
		logger.AuthELog.Tracef("Subtype AKA-Client-Error\n")
		if len(attributes) != 1 {
			return nil, fmt.Errorf("AKA-Client-Error attributes error")
		} else if _, ok := attributes[ausf_context.AT_CLIENT_ERROR_CODE_ATTRIBUTE]; !ok {
			return nil, fmt.Errorf("AKA-Client-Error attributes error")
		}
	default:
		logger.AuthELog.Tracef("subtype %x skipped\n", decodePkt.Subtype)
	}

	decodePkt.Attributes = attributes

	return &decodePkt, nil
}

func ConstructFailEapAkaNotification(oldPktId uint8) string {
	var eapPkt radius.EapPacket
	eapPkt.Code = radius.EapCodeRequest
	eapPkt.Identifier = oldPktId + 1
	eapPkt.Type = ausf_context.EAP_AKA_PRIME_TYPENUM

	eapAkaHdrBytes := make([]byte, 3)
	eapAkaHdrBytes[0] = ausf_context.AKA_NOTIFICATION_SUBTYPE

	attrNum := fmt.Sprintf("%02x", ausf_context.AT_NOTIFICATION_ATTRIBUTE)
	attribute := attrNum + "01" + "4000"
	var attrHex []byte
	if attrHexTmp, err := hex.DecodeString(attribute); err != nil {
		logger.AuthELog.Warnf("Decode attribute failed: %+v", err)
	} else {
		attrHex = attrHexTmp
	}

	eapPkt.Data = append(eapAkaHdrBytes, attrHex...)
	eapPktEncode := eapPkt.Encode()
	return base64.StdEncoding.EncodeToString(eapPktEncode)
}

func ConstructEapNoTypePkt(code radius.EapCode, pktID uint8) string {
	b := make([]byte, 4)
	b[0] = byte(code)
	b[1] = pktID
	binary.BigEndian.PutUint16(b[2:4], uint16(4))
	return base64.StdEncoding.EncodeToString(b)
}

func (p *Processor) logConfirmFailureAndInformUDM(
	id string, authType models.AuthType, servingNetworkName, errStr, udmUrl string,
) {
	if authType == models.AuthTypeN5GAKA {
		logger.Auth5gAkaLog.Infoln(servingNetworkName, errStr)
		if sendErr := p.Consumer().SendAuthResultToUDM(id, authType, false, "", udmUrl); sendErr != nil {
			logger.Auth5gAkaLog.Infoln(sendErr.Error())
		}
	} else if authType == models.AuthTypeEAPAKAPRIME {
		logger.AuthELog.Infoln(errStr)
		if sendErr := p.Consumer().SendAuthResultToUDM(id, authType, false, "", udmUrl); sendErr != nil {
			logger.AuthELog.Infoln(sendErr.Error())
		}
	}
}
