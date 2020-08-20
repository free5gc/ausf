package context

import (
	"fmt"
	"free5gc/lib/openapi/models"
	"free5gc/lib/path_util"
	"free5gc/src/ausf/factory"
	"free5gc/src/ausf/logger"
	"os"
	"strconv"

	"github.com/google/uuid"
)

func TestInit() {
	// load config
	DefaultAusfConfigPath := path_util.Gofree5gcPath("free5gc/config/ausfcfg.conf")
	factory.InitConfigFactory(DefaultAusfConfigPath)
	Init()
}

func InitAusfContext(context *AUSFContext) {
	config := factory.AusfConfig
	logger.InitLog.Infof("ausfconfig Info: Version[%s] Description[%s]\n", config.Info.Version, config.Info.Description)

	configuration := config.Configuration
	sbi := configuration.Sbi

	context.NfId = uuid.New().String()
	context.GroupId = configuration.GroupId
	context.NrfUri = configuration.NrfUri
	context.UriScheme = models.UriScheme(configuration.Sbi.Scheme) // default uri scheme
	context.HttpIPv4Address = "127.0.0.1"                          // default localhost
	context.HttpIpv4Port = 29509                                   // default port
	if sbi != nil {
		if sbi.RegisterIPv4 != "" {
			context.HttpIPv4Address = sbi.RegisterIPv4
		}
		if sbi.Port != 0 {
			context.HttpIpv4Port = sbi.Port
		}

		if sbi.Scheme == "https" {
			context.UriScheme = models.UriScheme_HTTPS
		} else {
			context.UriScheme = models.UriScheme_HTTP
		}

		context.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if context.BindingIPv4 == "" {
			logger.InitLog.Warn("Problem parsing ServerIPv4 address from ENV Variable. Trying to parse it as string.")
			context.BindingIPv4 = sbi.BindingIPv4
			if context.BindingIPv4 == "" {
				logger.InitLog.Warn("Error parsing ServerIPv4 address as string. Using the localhost address as default.")
				context.BindingIPv4 = "127.0.0.1"
			}
		}
	}

	context.Url = string(context.UriScheme) + "://" + context.HttpIPv4Address + ":" + strconv.Itoa(context.HttpIpv4Port)
	context.PlmnList = append(context.PlmnList, configuration.PlmnSupportList...)

	// context.NfService
	context.NfService = make(map[models.ServiceName]models.NfService)
	AddNfServices(&context.NfService, &config, context)
	fmt.Println("ausf context = ", context)
}

func AddNfServices(serviceMap *map[models.ServiceName]models.NfService, config *factory.Config, context *AUSFContext) {
	var nfService models.NfService
	var ipEndPoints []models.IpEndPoint
	var nfServiceVersions []models.NfServiceVersion
	services := *serviceMap

	// nausf-auth
	nfService.ServiceInstanceId = context.NfId
	nfService.ServiceName = models.ServiceName_NAUSF_AUTH

	var ipEndPoint models.IpEndPoint
	ipEndPoint.Ipv4Address = context.HttpIPv4Address
	ipEndPoint.Port = int32(context.HttpIpv4Port)
	ipEndPoints = append(ipEndPoints, ipEndPoint)

	var nfServiceVersion models.NfServiceVersion
	nfServiceVersion.ApiFullVersion = config.Info.Version
	nfServiceVersion.ApiVersionInUri = "v1"
	nfServiceVersions = append(nfServiceVersions, nfServiceVersion)

	nfService.Scheme = context.UriScheme
	nfService.NfServiceStatus = models.NfServiceStatus_REGISTERED

	nfService.IpEndPoints = &ipEndPoints
	nfService.Versions = &nfServiceVersions
	services[models.ServiceName_NAUSF_AUTH] = nfService
}
