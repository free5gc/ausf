package context

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ShouheiNishi/openapi5g/models"
	"github.com/google/uuid"

	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/ausf/pkg/factory"
	oldModels "github.com/free5gc/openapi/models"
)

func InitAusfContext(context *AUSFContext) {
	config := factory.AusfConfig
	logger.InitLog.Infof("ausfconfig Info: Version[%s] Description[%s]\n", config.Info.Version, config.Info.Description)

	configuration := config.Configuration
	sbi := configuration.Sbi

	context.NfId = uuid.New()
	context.GroupID = configuration.GroupId
	context.NrfUri = configuration.NrfUri
	context.NrfCertPem = configuration.NrfCertPem
	context.UriScheme = models.UriScheme(configuration.Sbi.Scheme) // default uri scheme
	context.RegisterIPv4 = factory.AusfSbiDefaultIPv4              // default localhost
	context.SBIPort = factory.AusfSbiDefaultPort                   // default port
	if sbi != nil {
		if sbi.RegisterIPv4 != "" {
			context.RegisterIPv4 = sbi.RegisterIPv4
		}
		if sbi.Port != 0 {
			context.SBIPort = sbi.Port
		}

		if sbi.Scheme == "https" {
			context.UriScheme = models.Https
		} else {
			context.UriScheme = models.Http
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
	context.NfService = make(map[oldModels.ServiceName]models.NrfNFService)
	AddNfServices(&context.NfService, config, context)
	fmt.Println("ausf context = ", context)

	context.EapAkaSupiImsiPrefix = configuration.EapAkaSupiImsiPrefix
}

func AddNfServices(serviceMap *map[oldModels.ServiceName]models.NrfNFService, config *factory.Config, context *AUSFContext) {
	var nfService models.NrfNFService
	var ipEndPoints []models.IpEndPoint
	var nfServiceVersions []models.NFServiceVersion
	services := *serviceMap

	// nausf-auth
	nfService.ServiceInstanceId = context.NfId.String()
	nfService.ServiceName = models.ServiceNameNausfAuth

	var ipEndPoint models.IpEndPoint
	ipEndPoint.Ipv4Address = context.RegisterIPv4
	ipEndPoint.Port = &context.SBIPort
	ipEndPoints = append(ipEndPoints, ipEndPoint)

	var nfServiceVersion models.NFServiceVersion
	nfServiceVersion.ApiFullVersion = config.Info.Version
	nfServiceVersion.ApiVersionInUri = "v1"
	nfServiceVersions = append(nfServiceVersions, nfServiceVersion)

	nfService.Scheme = context.UriScheme
	nfService.NfServiceStatus = models.NFServiceStatusREGISTERED

	nfService.IpEndPoints = ipEndPoints
	nfService.Versions = nfServiceVersions
	services[oldModels.ServiceName_NAUSF_AUTH] = nfService
}
