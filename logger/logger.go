package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	"free5gc/lib/logger_conf"
	"free5gc/lib/logger_util"
)

var log *logrus.Logger
var AppLog *logrus.Entry
var InitLog *logrus.Entry
var UeAuthPostLog *logrus.Entry
var Auth5gAkaComfirmLog *logrus.Entry
var EapAuthComfirmLog *logrus.Entry
var HandlerLog *logrus.Entry
var ContextLog *logrus.Entry
var GinLog *logrus.Entry

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	free5gcLogHook, err := logger_util.NewFileHook(logger_conf.Free5gcLogFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err == nil {
		log.Hooks.Add(free5gcLogHook)
	}

	selfLogHook, err := logger_util.NewFileHook(logger_conf.NfLogDir+"ausf.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err == nil {
		log.Hooks.Add(selfLogHook)
	}

	AppLog = log.WithFields(logrus.Fields{"component": "AUSF", "category": "App"})
	InitLog = log.WithFields(logrus.Fields{"component": "AUSF", "category": "Init"})
	UeAuthPostLog = log.WithFields(logrus.Fields{"component": "AUSF", "category": "UeAuthPost"})
	Auth5gAkaComfirmLog = log.WithFields(logrus.Fields{"component": "AUSF", "category": "5gAkaAuth"})
	EapAuthComfirmLog = log.WithFields(logrus.Fields{"component": "AUSF", "category": "EapAkaAuth"})
	HandlerLog = log.WithFields(logrus.Fields{"component": "AUSF", "category": "Handler"})
	GinLog = log.WithFields(logrus.Fields{"component": "AUSF", "category": "GIN"})
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(bool bool) {
	log.SetReportCaller(bool)
}
