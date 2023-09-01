package context

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ShouheiNishi/openapi5g/commondata"
	nrf_management "github.com/ShouheiNishi/openapi5g/nrf/management"
	"github.com/google/uuid"

	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/ausf/pkg/factory"
)

func InitAusfContext(context *AUSFContext) {
	config := factory.AusfConfig
	logger.InitLog.Infof("ausfconfig Info: Version[%s] Description[%s]\n", config.Info.Version, config.Info.Description)

	configuration := config.Configuration
	sbi := configuration.Sbi

	context.NfId = uuid.New().String()
	context.GroupID = configuration.GroupId
	context.NrfUri = configuration.NrfUri
	context.UriScheme = commondata.UriScheme(configuration.Sbi.Scheme) // default uri scheme
	context.RegisterIPv4 = factory.AusfSbiDefaultIPv4                  // default localhost
	context.SBIPort = factory.AusfSbiDefaultPort                       // default port
	if sbi != nil {
		if sbi.RegisterIPv4 != "" {
			context.RegisterIPv4 = sbi.RegisterIPv4
		}
		if sbi.Port != 0 {
			context.SBIPort = sbi.Port
		}

		if sbi.Scheme == "https" {
			context.UriScheme = commondata.Https
		} else {
			context.UriScheme = commondata.Http
		}

		context.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if context.BindingIPv4 != "" {
			logger.InitLog.Info("Parsing ServerIPv4 address from ENV Variable.")
		} else {
			context.BindingIPv4 = sbi.BindingIPv4
			if context.BindingIPv4 == "" {
				logger.InitLog.Warn("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
				context.BindingIPv4 = "0.0.0.0"
			}
		}
	}

	context.Url = string(context.UriScheme) + "://" + context.RegisterIPv4 + ":" + strconv.Itoa(context.SBIPort)
	context.PlmnList = append(context.PlmnList, configuration.PlmnSupportList...)

	// context.NfService
	context.NfService = make(map[nrf_management.ServiceName]nrf_management.NFService)
	AddNfServices(&context.NfService, config, context)
	fmt.Println("ausf context = ", context)

	context.EapAkaSupiImsiPrefix = configuration.EapAkaSupiImsiPrefix
}

func AddNfServices(serviceMap *map[nrf_management.ServiceName]nrf_management.NFService, config *factory.Config, context *AUSFContext) {
	var nfService nrf_management.NFService
	var ipEndPoints []nrf_management.IpEndPoint
	var nfServiceVersions []nrf_management.NFServiceVersion
	services := *serviceMap

	// nausf-auth
	nfService.ServiceInstanceId = context.NfId
	nfService.ServiceName = nrf_management.NausfAuth

	var ipEndPoint nrf_management.IpEndPoint
	ipEndPoint.Ipv4Address = &context.RegisterIPv4
	ipEndPoint.Port = &context.SBIPort
	ipEndPoints = append(ipEndPoints, ipEndPoint)

	var nfServiceVersion nrf_management.NFServiceVersion
	nfServiceVersion.ApiFullVersion = config.Info.Version
	nfServiceVersion.ApiVersionInUri = "v1"
	nfServiceVersions = append(nfServiceVersions, nfServiceVersion)

	nfService.Scheme = context.UriScheme
	nfService.NfServiceStatus = nrf_management.NFServiceStatusREGISTERED

	nfService.IpEndPoints = &ipEndPoints
	nfService.Versions = nfServiceVersions
	services[nrf_management.NausfAuth] = nfService
}
