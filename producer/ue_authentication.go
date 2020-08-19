package producer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/bronze1man/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"free5gc/lib/UeauCommon"
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi/models"
	ausf_context "free5gc/src/ausf/context"
	"free5gc/src/ausf/logger"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func HandleEapAuthComfirmRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.Auth5gAkaComfirmLog.Infof("EapAuthComfirmRequest")

	updateEapSession := request.Body.(models.EapSession)
	eapSessionID := request.Params["authCtxId"]

	response, problemDetails := EapAuthComfirmRequestProcedure(updateEapSession, eapSessionID)

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleAuth5gAkaComfirmRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.Auth5gAkaComfirmLog.Infof("Auth5gAkaComfirmRequest")
	updateConfirmationData := request.Body.(models.ConfirmationData)
	ConfirmationDataResponseID := request.Params["authCtxId"]

	response, problemDetails := Auth5gAkaComfirmRequestProcedure(updateConfirmationData, ConfirmationDataResponseID)
	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleUeAuthPostRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.UeAuthPostLog.Infof("HandleUeAuthPostRequest")
	updateAuthenticationInfo := request.Body.(models.AuthenticationInfo)

	response, locationURI, problemDetails := UeAuthPostRequestProcedure(updateAuthenticationInfo)
	respHeader := make(http.Header)
	respHeader.Set("Location", locationURI)

	if response != nil {
		return http_wrapper.NewResponse(http.StatusCreated, respHeader, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}
func UeAuthPostRequestProcedure(updateAuthenticationInfo models.AuthenticationInfo) (response *models.UeAuthenticationCtx, locationURI string, problemDetails *models.ProblemDetails) {
	var responseBody models.UeAuthenticationCtx
	var authInfoReq models.AuthenticationInfoRequest

	supiOrSuci := updateAuthenticationInfo.SupiOrSuci

	snName := updateAuthenticationInfo.ServingNetworkName
	servingNetworkAuthorized := ausf_context.IsServingNetworkAuthorized(snName)
	if !servingNetworkAuthorized {
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "SERVING_NETWORK_NOT_AUTHORIZED"
		logger.UeAuthPostLog.Infoln("403 forbidden: serving network NOT AUTHORIZED")
		return nil, "", &problemDetails
	}
	logger.UeAuthPostLog.Infoln("Serving network authorized")

	responseBody.ServingNetworkName = snName
	authInfoReq.ServingNetworkName = snName
	self := ausf_context.GetSelf()
	authInfoReq.AusfInstanceId = self.GetSelfID()

	udmUrl := getUdmUrl(self.NrfUri)
	client := createClientToUdmUeau(udmUrl)
	authInfoResult, _, err := client.GenerateAuthDataApi.GenerateAuthData(context.Background(), supiOrSuci, authInfoReq)
	if err != nil {
		logger.UeAuthPostLog.Infoln(err.Error())
		var problemDetails models.ProblemDetails
		if authInfoResult.AuthenticationVector == nil {
			problemDetails.Cause = "AV_GENERATION_PROBLEM"
		} else {
			problemDetails.Cause = "UPSTREAM_SERVER_ERROR"
		}
		return nil, "", &problemDetails
	}

	ueid := authInfoResult.Supi
	ausfUeContext := ausf_context.NewAusfUeContext(ueid)
	ausfUeContext.ServingNetworkName = snName
	ausfUeContext.AuthStatus = models.AuthResult_ONGOING
	ausfUeContext.UdmUeauUrl = udmUrl
	ausf_context.AddAusfUeContextToPool(ausfUeContext)

	logger.UeAuthPostLog.Infof("Add SuciSupiPair (%s, %s) to map.\n", supiOrSuci, ueid)
	ausf_context.AddSuciSupiPairToMap(supiOrSuci, ueid)

	locationURI = self.Url + "/nausf-auth/v1/ue-authentications/" + supiOrSuci
	putLink := locationURI
	if authInfoResult.AuthType == models.AuthType__5_G_AKA {
		logger.UeAuthPostLog.Infoln("Use 5G AKA auth method")
		putLink += "/5g-aka-confirmation"

		// Derive HXRES* from XRES*
		concat := authInfoResult.AuthenticationVector.Rand + authInfoResult.AuthenticationVector.XresStar
		hxresStarBytes, _ := hex.DecodeString(concat)
		hxresStarAll := sha256.Sum256(hxresStarBytes)
		hxresStar := hex.EncodeToString(hxresStarAll[16:]) // last 128 bits
		logger.Auth5gAkaComfirmLog.Infof("XresStar = %x\n", authInfoResult.AuthenticationVector.XresStar)

		// Derive Kseaf from Kausf
		Kausf := authInfoResult.AuthenticationVector.Kausf
		KausfDecode, _ := hex.DecodeString(Kausf)
		P0 := []byte(snName)
		Kseaf := UeauCommon.GetKDFValue(KausfDecode, UeauCommon.FC_FOR_KSEAF_DERIVATION, P0, UeauCommon.KDFLen(P0))
		ausfUeContext.XresStar = authInfoResult.AuthenticationVector.XresStar
		ausfUeContext.Kausf = Kausf
		ausfUeContext.Kseaf = hex.EncodeToString(Kseaf)

		var av5gAka models.Av5gAka
		av5gAka.Rand = authInfoResult.AuthenticationVector.Rand
		av5gAka.Autn = authInfoResult.AuthenticationVector.Autn
		av5gAka.HxresStar = hxresStar

		responseBody.Var5gAuthData = av5gAka

	} else if authInfoResult.AuthType == models.AuthType_EAP_AKA_PRIME {
		logger.UeAuthPostLog.Infoln("Use EAP-AKA' auth method")
		putLink += "/eap-session"

		identity := ueid
		ikPrime := authInfoResult.AuthenticationVector.IkPrime
		ckPrime := authInfoResult.AuthenticationVector.CkPrime
		RAND := authInfoResult.AuthenticationVector.Rand
		AUTN := authInfoResult.AuthenticationVector.Autn
		XRES := authInfoResult.AuthenticationVector.Xres
		ausfUeContext.XRES = XRES

		K_encr, K_aut, K_re, MSK, EMSK := eapAkaPrimePrf(ikPrime, ckPrime, identity)
		_, _, _, _, _ = K_encr, K_aut, K_re, MSK, EMSK
		ausfUeContext.K_aut = K_aut
		Kausf := EMSK[0:32]
		ausfUeContext.Kausf = Kausf
		KausfDecode, _ := hex.DecodeString(Kausf)
		P0 := []byte(snName)
		Kseaf := UeauCommon.GetKDFValue(KausfDecode, UeauCommon.FC_FOR_KSEAF_DERIVATION, P0, UeauCommon.KDFLen(P0))
		ausfUeContext.Kseaf = hex.EncodeToString(Kseaf)

		var eapPkt radius.EapPacket
		var randIdentifier int
		rand.Seed(time.Now().Unix())

		eapPkt.Code = radius.EapCode(1)
		randIdentifier = rand.Intn(256)
		eapPkt.Identifier = uint8(randIdentifier)
		eapPkt.Type = radius.EapType(50) // accroding to RFC5448 6.1
		atRand, _ := EapEncodeAttribute("AT_RAND", RAND)
		atAutn, _ := EapEncodeAttribute("AT_AUTN", AUTN)
		atKdf, _ := EapEncodeAttribute("AT_KDF", snName)
		atKdfInput, _ := EapEncodeAttribute("AT_KDF_INPUT", snName)
		atMAC, _ := EapEncodeAttribute("AT_MAC", "")

		dataArrayBeforeMAC := atRand + atAutn + atMAC + atKdf + atKdfInput
		eapPkt.Data = []byte(dataArrayBeforeMAC)
		encodedPktBeforeMAC := eapPkt.Encode()

		MACvalue := CalculateAtMAC([]byte(K_aut), encodedPktBeforeMAC)
		atMacNum := fmt.Sprintf("%02x", ausf_context.AT_MAC_ATTRIBUTE)
		atMACfirstRow, _ := hex.DecodeString(atMacNum + "05" + "0000")
		wholeAtMAC := append(atMACfirstRow, MACvalue...)

		atMAC = string(wholeAtMAC)
		dataArrayAfterMAC := atRand + atAutn + atMAC + atKdf + atKdfInput

		eapPkt.Data = []byte(dataArrayAfterMAC)
		encodedPktAfterMAC := eapPkt.Encode()
		responseBody.Var5gAuthData = base64.StdEncoding.EncodeToString(encodedPktAfterMAC)
	}

	var linksValue = models.LinksValueSchema{Href: putLink}
	responseBody.Links = make(map[string]models.LinksValueSchema)
	responseBody.Links["link"] = linksValue
	responseBody.AuthType = authInfoResult.AuthType

	return &responseBody, locationURI, nil
}

func Auth5gAkaComfirmRequestProcedure(updateConfirmationData models.ConfirmationData, ConfirmationDataResponseID string) (response *models.ConfirmationDataResponse, problemDetails *models.ProblemDetails) {
	var responseBody models.ConfirmationDataResponse
	success := false
	responseBody.AuthResult = models.AuthResult_FAILURE

	if !ausf_context.CheckIfSuciSupiPairExists(ConfirmationDataResponseID) {
		logger.Auth5gAkaComfirmLog.Infof("supiSuciPair does not exist, confirmation failed (queried by %s)\n", ConfirmationDataResponseID)
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "USER_NOT_FOUND"
		return nil, &problemDetails
	}

	currentSupi := ausf_context.GetSupiFromSuciSupiMap(ConfirmationDataResponseID)
	if !ausf_context.CheckIfAusfUeContextExists(currentSupi) {
		logger.Auth5gAkaComfirmLog.Infof("SUPI does not exist, confirmation failed (queried by %s)\n", currentSupi)
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "USER_NOT_FOUND"
		return nil, &problemDetails
	}

	ausfCurrentContext := ausf_context.GetAusfUeContext(currentSupi)
	servingNetworkName := ausfCurrentContext.ServingNetworkName

	// Compare the received RES* with the stored XRES*
	logger.Auth5gAkaComfirmLog.Infof("res*: %x\nXres*: %x\n", updateConfirmationData.ResStar, ausfCurrentContext.XresStar)
	if strings.Compare(updateConfirmationData.ResStar, ausfCurrentContext.XresStar) == 0 {
		ausfCurrentContext.AuthStatus = models.AuthResult_SUCCESS
		responseBody.AuthResult = models.AuthResult_SUCCESS
		success = true
		logger.Auth5gAkaComfirmLog.Infoln("5G AKA confirmation succeeded")
		responseBody.Kseaf = ausfCurrentContext.Kseaf
	} else {
		ausfCurrentContext.AuthStatus = models.AuthResult_FAILURE
		responseBody.AuthResult = models.AuthResult_FAILURE
		logConfirmFailureAndInformUDM(ConfirmationDataResponseID, models.AuthType__5_G_AKA, servingNetworkName, "5G AKA confirmation failed", ausfCurrentContext.UdmUeauUrl)
	}

	if sendErr := sendAuthResultToUDM(currentSupi, models.AuthType__5_G_AKA, success, servingNetworkName, ausfCurrentContext.UdmUeauUrl); sendErr != nil {
		logger.Auth5gAkaComfirmLog.Infoln(sendErr.Error())
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "UPSTREAM_SERVER_ERROR"

		return nil, &problemDetails
	}

	responseBody.Supi = currentSupi
	return &responseBody, nil
}

func EapAuthComfirmRequestProcedure(updateEapSession models.EapSession, eapSessionID string) (response *models.EapSession, problemDetails *models.ProblemDetails) {
	var responseBody models.EapSession

	if !ausf_context.CheckIfSuciSupiPairExists(eapSessionID) {
		logger.Auth5gAkaComfirmLog.Infoln("supiSuciPair does not exist, confirmation failed")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "USER_NOT_FOUND"
		return nil, &problemDetails
	}

	currentSupi := ausf_context.GetSupiFromSuciSupiMap(eapSessionID)
	if !ausf_context.CheckIfAusfUeContextExists(currentSupi) {
		logger.Auth5gAkaComfirmLog.Infoln("SUPI does not exist, confirmation failed")
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "USER_NOT_FOUND"
		return nil, &problemDetails
	}

	ausfCurrentContext := ausf_context.GetAusfUeContext(currentSupi)
	servingNetworkName := ausfCurrentContext.ServingNetworkName
	eapPayload, _ := base64.StdEncoding.DecodeString(updateEapSession.EapPayload)

	eapGoPkt := gopacket.NewPacket(eapPayload, layers.LayerTypeEAP, gopacket.Default)
	eapLayer := eapGoPkt.Layer(layers.LayerTypeEAP)
	eapContent, _ := eapLayer.(*layers.EAP)

	if eapContent.Code != layers.EAPCodeResponse {
		logConfirmFailureAndInformUDM(eapSessionID, models.AuthType_EAP_AKA_PRIME, servingNetworkName, "eap packet code error", ausfCurrentContext.UdmUeauUrl)
		ausfCurrentContext.AuthStatus = models.AuthResult_FAILURE
		responseBody.AuthResult = models.AuthResult_ONGOING
		failEapAkaNoti := ConstructFailEapAkaNotification(eapContent.Id)
		responseBody.EapPayload = failEapAkaNoti
		return &responseBody, nil
	}
	switch ausfCurrentContext.AuthStatus {
	case models.AuthResult_ONGOING:
		responseBody.KSeaf = ausfCurrentContext.Kseaf
		responseBody.Supi = currentSupi
		Kautn := ausfCurrentContext.K_aut
		XRES := ausfCurrentContext.XRES
		RES, decodeOK := decodeResMac(eapContent.TypeData, eapContent.Contents, Kautn)
		if !decodeOK {
			ausfCurrentContext.AuthStatus = models.AuthResult_FAILURE
			responseBody.AuthResult = models.AuthResult_ONGOING
			logConfirmFailureAndInformUDM(eapSessionID, models.AuthType_EAP_AKA_PRIME, servingNetworkName, "eap packet decode error", ausfCurrentContext.UdmUeauUrl)
			failEapAkaNoti := ConstructFailEapAkaNotification(eapContent.Id)
			responseBody.EapPayload = failEapAkaNoti

		} else if XRES == string(RES) { // decodeOK && XRES == res, auth success
			logger.EapAuthComfirmLog.Infoln("Correct RES value, EAP-AKA' auth succeed")
			responseBody.AuthResult = models.AuthResult_SUCCESS
			eapSuccPkt := ConstructEapNoTypePkt(radius.EapCodeSuccess, eapContent.Id)
			responseBody.EapPayload = eapSuccPkt
			udmUrl := ausfCurrentContext.UdmUeauUrl
			if sendErr := sendAuthResultToUDM(eapSessionID, models.AuthType_EAP_AKA_PRIME, true, servingNetworkName, udmUrl); sendErr != nil {
				logger.EapAuthComfirmLog.Infoln(sendErr.Error())
				var problemDetails models.ProblemDetails
				problemDetails.Cause = "UPSTREAM_SERVER_ERROR"
				return nil, &problemDetails
			}
			ausfCurrentContext.AuthStatus = models.AuthResult_SUCCESS

		} else {
			ausfCurrentContext.AuthStatus = models.AuthResult_FAILURE
			responseBody.AuthResult = models.AuthResult_ONGOING
			logConfirmFailureAndInformUDM(eapSessionID, models.AuthType_EAP_AKA_PRIME, servingNetworkName, "Wrong RES value, EAP-AKA' auth failed", ausfCurrentContext.UdmUeauUrl)
			failEapAkaNoti := ConstructFailEapAkaNotification(eapContent.Id)
			responseBody.EapPayload = failEapAkaNoti
		}

	case models.AuthResult_FAILURE:
		eapFailPkt := ConstructEapNoTypePkt(radius.EapCodeFailure, uint8(eapPayload[1]))
		responseBody.EapPayload = eapFailPkt
		responseBody.AuthResult = models.AuthResult_FAILURE
	}

	return &responseBody, nil
}
