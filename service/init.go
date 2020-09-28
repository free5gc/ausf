package service

import (
	"bufio"
	"fmt"
	"free5gc/lib/http2_util"
	"free5gc/lib/logger_util"
	"free5gc/lib/path_util"
	"free5gc/src/app"
	"free5gc/src/ausf/consumer"
	ausf_context "free5gc/src/ausf/context"
	"free5gc/src/ausf/factory"
	"free5gc/src/ausf/logger"
	"free5gc/src/ausf/ueauthentication"
	"free5gc/src/ausf/util"
	"os/exec"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type AUSF struct{}

type (
	// Config information.
	Config struct {
		ausfcfg string
	}
)

var config Config

var ausfCLi = []cli.Flag{
	cli.StringFlag{
		Name:  "free5gccfg",
		Usage: "common config file",
	},
	cli.StringFlag{
		Name:  "ausfcfg",
		Usage: "config file",
	},
}

var initLog *logrus.Entry

func init() {
	initLog = logger.InitLog
}

func (*AUSF) GetCliCmd() (flags []cli.Flag) {
	return ausfCLi
}

func (*AUSF) Initialize(c *cli.Context) {

	config = Config{
		ausfcfg: c.String("ausfcfg"),
	}

	if config.ausfcfg != "" {
		factory.InitConfigFactory(config.ausfcfg)
	} else {
		DefaultAusfConfigPath := path_util.Gofree5gcPath("free5gc/config/ausfcfg.conf")
		factory.InitConfigFactory(DefaultAusfConfigPath)
	}

	if app.ContextSelf().Logger.AUSF.DebugLevel != "" {
		level, err := logrus.ParseLevel(app.ContextSelf().Logger.AUSF.DebugLevel)
		if err != nil {
			initLog.Warnf("Log level [%s] is not valid, set to [info] level", app.ContextSelf().Logger.AUSF.DebugLevel)
			logger.SetLogLevel(logrus.InfoLevel)
		} else {
			logger.SetLogLevel(level)
			initLog.Infof("Log level is set to [%s] level", level)
		}
	} else {
		initLog.Infoln("Log level is default set to [info] level")
		logger.SetLogLevel(logrus.InfoLevel)
	}

	logger.SetReportCaller(app.ContextSelf().Logger.AUSF.ReportCaller)

}

func (ausf *AUSF) FilterCli(c *cli.Context) (args []string) {
	for _, flag := range ausf.GetCliCmd() {
		name := flag.GetName()
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (ausf *AUSF) Start() {
	initLog.Infoln("Server started")

	router := logger_util.NewGinWithLogrus(logger.GinLog)
	ueauthentication.AddService(router)

	ausf_context.Init()
	self := ausf_context.GetSelf()
	// Register to NRF
	profile, err := consumer.BuildNFInstance(self)
	if err != nil {
		initLog.Error("Build AUSF Profile Error")
	}
	_, self.NfId, err = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, profile)
	if err != nil {
		initLog.Errorf("AUSF register to NRF Error[%s]", err.Error())
	}

	ausfLogPath := util.AusfLogPath

	addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)

	server, err := http2_util.NewServer(addr, ausfLogPath, router)
	if server == nil {
		initLog.Errorf("Initialize HTTP server failed: %+v", err)
		return
	}

	if err != nil {
		initLog.Warnf("Initialize HTTP server: +%v", err)
	}

	serverScheme := factory.AusfConfig.Configuration.Sbi.Scheme
	if serverScheme == "http" {
		err = server.ListenAndServe()
	} else if serverScheme == "https" {
		err = server.ListenAndServeTLS(util.AusfPemPath, util.AusfKeyPath)
	}

	if err != nil {
		initLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (ausf *AUSF) Exec(c *cli.Context) error {

	initLog.Traceln("args:", c.String("ausfcfg"))
	args := ausf.FilterCli(c)
	initLog.Traceln("filter: ", args)
	command := exec.Command("./ausf", args...)

	stdout, err := command.StdoutPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	wg := sync.WaitGroup{}
	wg.Add(3)
	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stderr)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		startErr := command.Start()
		if startErr != nil {
			initLog.Fatalln(startErr)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}
