package producer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"net/http"
	"strings"
	"time"

	ausf_authentication "github.com/ShouheiNishi/openapi5g/ausf/authentication"
	"github.com/ShouheiNishi/openapi5g/commondata"
	udm_ueau "github.com/ShouheiNishi/openapi5g/udm/ueau"
	"github.com/bronze1man/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/samber/lo"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/ausf/pkg/factory"
	"github.com/free5gc/util/ueauth"
)

func NewServerAusfAuthentication() ausf_authentication.ServerInterface {
	return ausf_authentication.NewStrictHandler(ausfAuthenticationStrictServerInterface{}, nil)
}

// s ausfAuthenticationStrictServerInterface ausf_authentication.StrictServerInterface
type ausfAuthenticationStrictServerInterface struct{}

// TODO: move to other package
func GetNotImplementedProblemDetails(status int) commondata.ProblemDetails {
	return commondata.ProblemDetails{
		Cause:  lo.ToPtr("NOT_IMPLEMENTED"),
		Detail: lo.ToPtr("not implemented"),
		Status: lo.ToPtr(status),
	}
}

// (POST /rg-authentications)
func (s ausfAuthenticationStrictServerInterface) PostRgAuthentications(ctx context.Context,
	request ausf_authentication.PostRgAuthenticationsRequestObject,
) (ausf_authentication.PostRgAuthenticationsResponseObject, error) {
	return ausf_authentication.
		PostRgAuthentications400ApplicationProblemPlusJSONResponse(GetNotImplementedProblemDetails(400)), nil
}

// (POST /ue-authentications/deregister)
func (s ausfAuthenticationStrictServerInterface) PostUeAuthenticationsDeregister(ctx context.Context,
	request ausf_authentication.PostUeAuthenticationsDeregisterRequestObject,
) (ausf_authentication.PostUeAuthenticationsDeregisterResponseObject, error) {
	return ausf_authentication.PostUeAuthenticationsDeregister404ApplicationProblemPlusJSONResponse{
		N404ApplicationProblemPlusJSONResponse: commondata.N404ApplicationProblemPlusJSONResponse(
			GetNotImplementedProblemDetails(404)),
	}, nil
}

// Deletes the authentication result in the UDM
// (DELETE /ue-authentications/{authCtxId}/5g-aka-confirmation)
func (s ausfAuthenticationStrictServerInterface) Delete5gAkaAuthenticationResult(ctx context.Context,
	request ausf_authentication.Delete5gAkaAuthenticationResultRequestObject,
) (ausf_authentication.Delete5gAkaAuthenticationResultResponseObject, error) {
	return ausf_authentication.Delete5gAkaAuthenticationResult500ApplicationProblemPlusJSONResponse{
		N500ApplicationProblemPlusJSONResponse: commondata.N500ApplicationProblemPlusJSONResponse(
			GetNotImplementedProblemDetails(500)),
	}, nil
}

// Deletes the authentication result in the UDM
// (DELETE /ue-authentications/{authCtxId}/eap-session)
func (s ausfAuthenticationStrictServerInterface) DeleteEapAuthenticationResult(ctx context.Context,
	request ausf_authentication.DeleteEapAuthenticationResultRequestObject,
) (ausf_authentication.DeleteEapAuthenticationResultResponseObject, error) {
	return ausf_authentication.DeleteEapAuthenticationResult500ApplicationProblemPlusJSONResponse{
		N500ApplicationProblemPlusJSONResponse: commondata.N500ApplicationProblemPlusJSONResponse(
			GetNotImplementedProblemDetails(500)),
	}, nil
}

// // (POST /ue-authentications)
func (s ausfAuthenticationStrictServerInterface) PostUeAuthentications(ctx context.Context,
	request ausf_authentication.PostUeAuthenticationsRequestObject,
) (ausf_authentication.PostUeAuthenticationsResponseObject, error) {
	logger.UeAuthLog.Infof("PostUeAuthentications")

	if request.Body == nil {
		return ausf_authentication.PostUeAuthentications400ApplicationProblemPlusJSONResponse{
			Cause:  lo.ToPtr("BODY_NOT_EXIST"),
			Status: lo.ToPtr(http.StatusBadRequest),
		}, nil
	}

	updateAuthenticationInfo := *request.Body

	response, locationURI, problemDetails := UeAuthPostRequestProcedure(updateAuthenticationInfo)

	if response != nil {
		return ausf_authentication.PostUeAuthentications201Application3gppHalPlusJSONResponse{
			Body: *response,
			Headers: ausf_authentication.PostUeAuthentications201ResponseHeaders{
				Location: locationURI,
			},
		}, nil
	} else if problemDetails != nil {
		var status int
		if problemDetails.Status != nil {
			status = *problemDetails.Status
		}
		switch status {
		case 400:
			return ausf_authentication.PostUeAuthentications400ApplicationProblemPlusJSONResponse(*problemDetails), nil
		case 403:
			return ausf_authentication.PostUeAuthentications403ApplicationProblemPlusJSONResponse(*problemDetails), nil
		case 404:
			return ausf_authentication.PostUeAuthentications404ApplicationProblemPlusJSONResponse(*problemDetails), nil
		default:
			problemDetails.Status = lo.ToPtr(500)
			fallthrough
		case 500:
			return ausf_authentication.PostUeAuthentications500ApplicationProblemPlusJSONResponse(*problemDetails), nil
		case 501:
			return ausf_authentication.PostUeAuthentications501ApplicationProblemPlusJSONResponse(*problemDetails), nil
		}
	}
	problemDetails = &commondata.ProblemDetails{
		Status: lo.ToPtr(http.StatusForbidden),
		Cause:  lo.ToPtr("UNSPECIFIED"),
	}
	return ausf_authentication.PostUeAuthentications403ApplicationProblemPlusJSONResponse(*problemDetails), nil
}

// func UeAuthPostRequestProcedure(updateAuthenticationInfo models.AuthenticationInfo) (
//
//	response *models.UeAuthenticationCtx, locationURI string, problemDetails *models.ProblemDetails) {
func UeAuthPostRequestProcedure(updateAuthenticationInfo ausf_authentication.AuthenticationInfo,
) (*ausf_authentication.UEAuthenticationCtx, string, *commondata.ProblemDetails,
) {
	var responseBody ausf_authentication.UEAuthenticationCtx
	var authInfoReq udm_ueau.AuthenticationInfoRequest

	supiOrSuci := updateAuthenticationInfo.SupiOrSuci

	snName := updateAuthenticationInfo.ServingNetworkName
	servingNetworkAuthorized := ausf_context.IsServingNetworkAuthorized(snName)
	if !servingNetworkAuthorized {
		var problemDetails commondata.ProblemDetails
		problemDetails.Cause = lo.ToPtr("SERVING_NETWORK_NOT_AUTHORIZED")
		problemDetails.Status = lo.ToPtr(http.StatusForbidden)
		logger.UeAuthLog.Infoln("403 forbidden: serving network NOT AUTHORIZED")
		return nil, "", &problemDetails
	}
	logger.UeAuthLog.Infoln("Serving network authorized")

	responseBody.ServingNetworkName = &snName
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

	udmUrl := getUdmUrl(self.NrfUri)
	client, err := createClientToUdmUeau(udmUrl)
	if err != nil {
		return nil, "", &commondata.ProblemDetails{
			Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
			Detail: lo.ToPtr(err.Error()),
			Status: lo.ToPtr(http.StatusInternalServerError),
		}
	}
	rsp, err := client.GenerateAuthDataWithResponse(context.Background(), supiOrSuci, authInfoReq)
	if err != nil {
		return nil, "", &commondata.ProblemDetails{
			Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
			Detail: lo.ToPtr(err.Error()),
			Status: lo.ToPtr(http.StatusInternalServerError),
		}
	} else if rsp.JSON200 == nil {
		return nil, "", &commondata.ProblemDetails{
			Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
			Detail: lo.ToPtr(rsp.Status()),
			Status: lo.ToPtr(http.StatusInternalServerError),
		}
	}
	authInfoResult := rsp.JSON200

	if authInfoResult.Supi == nil {
		return nil, "", &commondata.ProblemDetails{
			Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
			Detail: lo.ToPtr("no SUPI"),
			Status: lo.ToPtr(http.StatusInternalServerError),
		}
	}
	ueid := *authInfoResult.Supi
	ausfUeContext := ausf_context.NewAusfUeContext(ueid)
	ausfUeContext.ServingNetworkName = snName
	ausfUeContext.AuthStatus = ausf_authentication.AUTHENTICATIONONGOING
	ausfUeContext.UdmUeauUrl = udmUrl
	ausf_context.AddAusfUeContextToPool(ausfUeContext)

	logger.UeAuthLog.Infof("Add SuciSupiPair (%s, %s) to map.\n", supiOrSuci, ueid)
	ausf_context.AddSuciSupiPairToMap(supiOrSuci, ueid)

	locationURI := self.Url + factory.AusfAuthResUriPrefix + "/ue-authentications/" + supiOrSuci
	putLink := locationURI
	if authInfoResult.AuthType == udm_ueau.AuthTypeN5GAKA {
		logger.UeAuthLog.Infoln("Use 5G AKA auth method")
		putLink += "/5g-aka-confirmation"

		var av5GHeAka udm_ueau.Av5GHeAka
		if av5GHeAka_tmp, err := authInfoResult.AuthenticationVector.AsAv5GHeAka(); err != nil {
			return nil, "", &commondata.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: lo.ToPtr(http.StatusInternalServerError),
			}
		} else {
			av5GHeAka = av5GHeAka_tmp
		}

		// Derive HXRES* from XRES*
		concat := av5GHeAka.Rand + av5GHeAka.XresStar
		var hxresStarBytes []byte
		if bytes, err := hex.DecodeString(concat); err != nil {
			logger.Auth5gAkaLog.Errorf("decode concat error: %+v", err)
			return nil, "",
				&commondata.ProblemDetails{
					Title:  lo.ToPtr("Concat Decode Problem"),
					Cause:  lo.ToPtr("CONCAT_DECODE_PROBLEM"),
					Detail: lo.ToPtr(err.Error()),
					Status: lo.ToPtr(http.StatusInternalServerError),
				}
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
			return nil, "",
				&commondata.ProblemDetails{
					Title:  lo.ToPtr("Kausf Decode Problem"),
					Cause:  lo.ToPtr("KAUSF_DECODE_PROBLEM"),
					Detail: lo.ToPtr(err.Error()),
					Status: lo.ToPtr(http.StatusInternalServerError),
				}
		} else {
			KausfDecode = ausfDecode
		}
		P0 := []byte(snName)
		Kseaf, err := ueauth.GetKDFValue(KausfDecode, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))
		if err != nil {
			logger.Auth5gAkaLog.Errorf("GetKDFValue failed: %+v", err)
			return nil, "",
				&commondata.ProblemDetails{
					Title:  lo.ToPtr("Kseaf Derivation Problem"),
					Cause:  lo.ToPtr("KSEAF_DERIVATION_PROBLEM"),
					Detail: lo.ToPtr(err.Error()),
					Status: lo.ToPtr(http.StatusInternalServerError),
				}
		}
		ausfUeContext.XresStar = av5GHeAka.XresStar
		ausfUeContext.Kausf = Kausf
		ausfUeContext.Kseaf = hex.EncodeToString(Kseaf)
		ausfUeContext.Rand = av5GHeAka.Rand

		var av5gAka ausf_authentication.Av5gAka
		av5gAka.Rand = av5GHeAka.Rand
		av5gAka.Autn = av5GHeAka.Autn
		av5gAka.HxresStar = hxresStar
		if err := responseBody.N5gAuthData.FromAv5gAka(av5gAka); err != nil {
			return nil, "", &commondata.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: lo.ToPtr(http.StatusInternalServerError),
			}
		}

		var linksValue commondata.LinksValueSchema
		if err := linksValue.FromLink(commondata.Link{Href: &putLink}); err != nil {
			return nil, "", &commondata.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: lo.ToPtr(http.StatusInternalServerError),
			}
		}
		responseBody.Links = make(map[string]commondata.LinksValueSchema)
		responseBody.Links["5g-aka"] = linksValue
	} else if authInfoResult.AuthType == udm_ueau.AuthTypeEAPAKAPRIME {
		logger.UeAuthLog.Infoln("Use EAP-AKA' auth method")
		putLink += "/eap-session"

		avEapAkaPrime, err := authInfoResult.AuthenticationVector.AsAvEapAkaPrime()
		if err != nil {
			return nil, "", &commondata.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: lo.ToPtr(http.StatusInternalServerError),
			}
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
			rand.Seed(time.Now().Unix())
			randIdentifier := rand.Intn(256)
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
		if err := responseBody.N5gAuthData.FromEapPayload(base64.StdEncoding.EncodeToString(encodedPktAfterMAC)); err != nil {
			return nil, "", &commondata.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: lo.ToPtr(http.StatusInternalServerError),
			}
		}

		var linksValue commondata.LinksValueSchema
		if err := linksValue.FromLink(commondata.Link{Href: &putLink}); err != nil {
			return nil, "", &commondata.ProblemDetails{
				Cause:  lo.ToPtr("UDM_CLIENT_FAIL"),
				Detail: lo.ToPtr(err.Error()),
				Status: lo.ToPtr(http.StatusInternalServerError),
			}
		}
		responseBody.Links = make(map[string]commondata.LinksValueSchema)
		responseBody.Links["eap-session"] = linksValue
	}

	responseBody.AuthType = ausf_authentication.AuthType(authInfoResult.AuthType)

	return &responseBody, locationURI, nil
}

// (PUT /ue-authentications/{authCtxId}/5g-aka-confirmation)
func (s ausfAuthenticationStrictServerInterface) PutUeAuthenticationsAuthCtxId5gAkaConfirmation(ctx context.Context,
	request ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmationRequestObject,
) (ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmationResponseObject, error) {
	logger.Auth5gAkaLog.Infof("PutUeAuthenticationsAuthCtxId5gAkaConfirmation")
	updateConfirmationData := request.Body
	ConfirmationDataResponseID := request.AuthCtxId

	var responseBody ausf_authentication.ConfirmationDataResponse
	success := false
	responseBody.AuthResult = ausf_authentication.AUTHENTICATIONFAILURE

	if !ausf_context.CheckIfSuciSupiPairExists(ConfirmationDataResponseID) {
		logger.Auth5gAkaLog.Infof("supiSuciPair does not exist, confirmation failed (queried by %s)\n",
			ConfirmationDataResponseID)
		var problemDetails commondata.ProblemDetails
		problemDetails.Cause = lo.ToPtr("USER_NOT_FOUND")
		problemDetails.Status = lo.ToPtr(http.StatusBadRequest)
		return ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmation400ApplicationProblemPlusJSONResponse(
			problemDetails), nil
	}

	currentSupi := ausf_context.GetSupiFromSuciSupiMap(ConfirmationDataResponseID)
	if !ausf_context.CheckIfAusfUeContextExists(currentSupi) {
		logger.Auth5gAkaLog.Infof("SUPI does not exist, confirmation failed (queried by %s)\n", currentSupi)
		var problemDetails commondata.ProblemDetails
		problemDetails.Cause = lo.ToPtr("USER_NOT_FOUND")
		problemDetails.Status = lo.ToPtr(http.StatusBadRequest)
		return ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmation400ApplicationProblemPlusJSONResponse(
			problemDetails), nil
	}

	ausfCurrentContext := ausf_context.GetAusfUeContext(currentSupi)
	servingNetworkName := ausfCurrentContext.ServingNetworkName

	// Compare the received RES* with the stored XRES*
	logger.Auth5gAkaLog.Infof("res*: %v\nXres*: %x\n", updateConfirmationData.ResStar, ausfCurrentContext.XresStar)
	if updateConfirmationData.ResStar != nil &&
		strings.EqualFold(*updateConfirmationData.ResStar, ausfCurrentContext.XresStar) {
		ausfCurrentContext.AuthStatus = ausf_authentication.AUTHENTICATIONSUCCESS
		responseBody.AuthResult = ausf_authentication.AUTHENTICATIONSUCCESS
		success = true
		logger.Auth5gAkaLog.Infoln("5G AKA confirmation succeeded")
		responseBody.Supi = &currentSupi
		responseBody.Kseaf = &ausfCurrentContext.Kseaf
	} else {
		ausfCurrentContext.AuthStatus = ausf_authentication.AUTHENTICATIONFAILURE
		responseBody.AuthResult = ausf_authentication.AUTHENTICATIONFAILURE
		logConfirmFailureAndInformUDM(ConfirmationDataResponseID, udm_ueau.AuthTypeN5GAKA, servingNetworkName,
			"5G AKA confirmation failed", ausfCurrentContext.UdmUeauUrl)
	}

	if sendErr := sendAuthResultToUDM(currentSupi, udm_ueau.AuthTypeN5GAKA, success, servingNetworkName,
		ausfCurrentContext.UdmUeauUrl); sendErr != nil {
		logger.Auth5gAkaLog.Infoln(sendErr.Error())
		var problemDetails commondata.ProblemDetails
		problemDetails.Status = lo.ToPtr(http.StatusInternalServerError)
		problemDetails.Cause = lo.ToPtr("UPSTREAM_SERVER_ERROR")

		return ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmation500ApplicationProblemPlusJSONResponse(
			problemDetails), nil
	}

	return ausf_authentication.PutUeAuthenticationsAuthCtxId5gAkaConfirmation200JSONResponse(responseBody), nil
}

// (POST /ue-authentications/{authCtxId}/eap-session)
func (s ausfAuthenticationStrictServerInterface) EapAuthMethod(ctx context.Context,
	request ausf_authentication.EapAuthMethodRequestObject,
) (ausf_authentication.EapAuthMethodResponseObject, error) {
	logger.Auth5gAkaLog.Infof("EapAuthMethod")
	updateEapSession := request.Body
	eapSessionID := request.AuthCtxId

	var responseBody ausf_authentication.EapSession

	if !ausf_context.CheckIfSuciSupiPairExists(eapSessionID) {
		logger.AuthELog.Infoln("supiSuciPair does not exist, confirmation failed")
		var problemDetails commondata.ProblemDetails
		problemDetails.Cause = lo.ToPtr("USER_NOT_FOUND")
		problemDetails.Status = lo.ToPtr(http.StatusBadRequest)
		return ausf_authentication.EapAuthMethod400ApplicationProblemPlusJSONResponse(problemDetails), nil
	}

	currentSupi := ausf_context.GetSupiFromSuciSupiMap(eapSessionID)
	if !ausf_context.CheckIfAusfUeContextExists(currentSupi) {
		logger.AuthELog.Infoln("SUPI does not exist, confirmation failed")
		var problemDetails commondata.ProblemDetails
		problemDetails.Cause = lo.ToPtr("USER_NOT_FOUND")
		problemDetails.Status = lo.ToPtr(http.StatusBadRequest)
		return ausf_authentication.EapAuthMethod400ApplicationProblemPlusJSONResponse(problemDetails), nil
	}

	ausfCurrentContext := ausf_context.GetAusfUeContext(currentSupi)
	servingNetworkName := ausfCurrentContext.ServingNetworkName

	if ausfCurrentContext.AuthStatus == ausf_authentication.AUTHENTICATIONFAILURE {
		eapFailPkt := ConstructEapNoTypePkt(radius.EapCodeFailure, 0)
		responseBody.EapPayload = &eapFailPkt
		responseBody.AuthResult = lo.ToPtr(ausf_authentication.AUTHENTICATIONFAILURE)
		return ausf_authentication.EapAuthMethod200JSONResponse(responseBody), nil
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
	if eapContent == nil {
		eapFailPkt := ConstructEapNoTypePkt(radius.EapCodeFailure, 0)
		responseBody.EapPayload = &eapFailPkt
		responseBody.AuthResult = lo.ToPtr(ausf_authentication.AUTHENTICATIONFAILURE)
		return ausf_authentication.EapAuthMethod200JSONResponse(responseBody), nil
	}

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
				responseBody.KSeaf = &ausfCurrentContext.Kseaf
				responseBody.Supi = &currentSupi
				responseBody.AuthResult = lo.ToPtr(ausf_authentication.AUTHENTICATIONSUCCESS)
				eapSuccPkt := ConstructEapNoTypePkt(radius.EapCodeSuccess, eapContent.Id)
				responseBody.EapPayload = &eapSuccPkt
				udmUrl := ausfCurrentContext.UdmUeauUrl
				if sendErr := sendAuthResultToUDM(
					eapSessionID,
					udm_ueau.AuthTypeEAPAKAPRIME,
					true,
					servingNetworkName,
					udmUrl); sendErr != nil {
					logger.AuthELog.Infoln(sendErr.Error())
					var problemDetails commondata.ProblemDetails
					problemDetails.Cause = lo.ToPtr("UPSTREAM_SERVER_ERROR")
					problemDetails.Status = lo.ToPtr(http.StatusInternalServerError)
					return ausf_authentication.EapAuthMethod500ApplicationProblemPlusJSONResponse(problemDetails), nil
				}
				ausfCurrentContext.AuthStatus = ausf_authentication.AUTHENTICATIONSUCCESS
			} else {
				eapOK = false
				eapErrStr = "Wrong RES value, EAP-AKA' auth failed"
			}
		case ausf_context.AKA_AUTHENTICATION_REJECT_SUBTYPE:
			ausfCurrentContext.AuthStatus = ausf_authentication.AUTHENTICATIONFAILURE
		case ausf_context.AKA_SYNCHRONIZATION_FAILURE_SUBTYPE:
			logger.AuthELog.Warnf("EAP-AKA' synchronziation failure")
			if ausfCurrentContext.Resynced {
				eapOK = false
				eapErrStr = "2 consecutive Synch Failure, terminate authentication procedure"
			} else {
				var authInfo ausf_authentication.AuthenticationInfo
				AUTS := decodeEapAkaPrimePkt.Attributes[ausf_context.AT_AUTS_ATTRIBUTE].Value
				resynchronizationInfo := &udm_ueau.ResynchronizationInfo{
					Auts: hex.EncodeToString(AUTS[:]),
				}
				authInfo.SupiOrSuci = eapSessionID
				authInfo.ServingNetworkName = servingNetworkName
				authInfo.ResynchronizationInfo = resynchronizationInfo
				response, _, problemDetails := UeAuthPostRequestProcedure(authInfo)
				if problemDetails != nil {
					var status int
					if problemDetails.Status != nil {
						status = *problemDetails.Status
					}
					switch status {
					case 400:
						return ausf_authentication.EapAuthMethod400ApplicationProblemPlusJSONResponse(*problemDetails), nil
					default:
						problemDetails.Status = lo.ToPtr(500)
						fallthrough
					case 500:
						return ausf_authentication.EapAuthMethod500ApplicationProblemPlusJSONResponse(*problemDetails), nil
					}
				}
				ausfCurrentContext.Resynced = true

				eapPayload, err := response.N5gAuthData.AsEapPayload()
				if err != nil {
					var problemDetails commondata.ProblemDetails
					problemDetails.Cause = lo.ToPtr("EAP_DECODE_ERROR")
					problemDetails.Detail = lo.ToPtr(err.Error())
					problemDetails.Status = lo.ToPtr(http.StatusInternalServerError)
					return ausf_authentication.EapAuthMethod500ApplicationProblemPlusJSONResponse(problemDetails), nil
				}
				responseBody.EapPayload = &eapPayload
				responseBody.Links = &response.Links
				responseBody.AuthResult = lo.ToPtr(ausf_authentication.AUTHENTICATIONONGOING)
			}
		case ausf_context.AKA_NOTIFICATION_SUBTYPE:
			ausfCurrentContext.AuthStatus = ausf_authentication.AUTHENTICATIONFAILURE
		case ausf_context.AKA_CLIENT_ERROR_SUBTYPE:
			logger.AuthELog.Warnf("EAP-AKA' failure: receive client-error")
			ausfCurrentContext.AuthStatus = ausf_authentication.AUTHENTICATIONFAILURE
		default:
			ausfCurrentContext.AuthStatus = ausf_authentication.AUTHENTICATIONFAILURE
		}
	}

	if !eapOK {
		logger.AuthELog.Warnf("EAP-AKA' failure: %s", eapErrStr)
		if sendErr := sendAuthResultToUDM(eapSessionID, udm_ueau.AuthTypeEAPAKAPRIME, false, servingNetworkName,
			ausfCurrentContext.UdmUeauUrl); sendErr != nil {
			logger.AuthELog.Infoln(sendErr.Error())
			var problemDetails commondata.ProblemDetails
			problemDetails.Status = lo.ToPtr(http.StatusInternalServerError)
			problemDetails.Cause = lo.ToPtr("UPSTREAM_SERVER_ERROR")

			return ausf_authentication.EapAuthMethod500ApplicationProblemPlusJSONResponse(problemDetails), nil
		}

		ausfCurrentContext.AuthStatus = ausf_authentication.AUTHENTICATIONFAILURE
		responseBody.AuthResult = lo.ToPtr(ausf_authentication.AUTHENTICATIONONGOING)
		failEapAkaNoti := ConstructFailEapAkaNotification(eapContent.Id)
		responseBody.EapPayload = &failEapAkaNoti
		self := ausf_context.GetSelf()
		linkUrl := self.Url + factory.AusfAuthResUriPrefix + "/ue-authentications/" + eapSessionID + "/eap-session"
		var linksValue commondata.LinksValueSchema
		if err := linksValue.FromLink(commondata.Link{Href: &linkUrl}); err != nil {
			return nil, err
		}
		responseBody.Links = &map[string]commondata.LinksValueSchema{}
		(*responseBody.Links)["eap-session"] = linksValue
	} else if ausfCurrentContext.AuthStatus == ausf_authentication.AUTHENTICATIONFAILURE {
		if sendErr := sendAuthResultToUDM(eapSessionID, udm_ueau.AuthTypeEAPAKAPRIME, false, servingNetworkName,
			ausfCurrentContext.UdmUeauUrl); sendErr != nil {
			logger.AuthELog.Infoln(sendErr.Error())
			var problemDetails commondata.ProblemDetails
			problemDetails.Status = lo.ToPtr(http.StatusInternalServerError)
			problemDetails.Cause = lo.ToPtr("UPSTREAM_SERVER_ERROR")

			return ausf_authentication.EapAuthMethod500ApplicationProblemPlusJSONResponse(problemDetails), nil
		}

		eapFailPkt := ConstructEapNoTypePkt(radius.EapCodeFailure, eapPayload[1])
		responseBody.EapPayload = &eapFailPkt
		responseBody.AuthResult = lo.ToPtr(ausf_authentication.AUTHENTICATIONFAILURE)
	}

	return ausf_authentication.EapAuthMethod200JSONResponse(responseBody), nil
}
