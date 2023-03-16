/*
 * AUSF Configuration Factory
 */

package factory

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/asaskevich/govalidator"

	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/openapi/models"
)

const (
	AusfDefaultTLSKeyLogPath      = "./log/ausfsslkey.log"
	AusfDefaultCertPemPath        = "./cert/ausf.pem"
	AusfDefaultPrivateKeyPath     = "./cert/ausf.key"
	AusfDefaultConfigPath         = "./config/ausfcfg.yaml"
	AusfSbiDefaultIPv4            = "127.0.0.9"
	AusfSbiDefaultPort            = 8000
	AusfSbiDefaultScheme          = "https"
	AusfDefaultNrfUri             = "https://127.0.0.10:8000"
	AusfSorprotectionResUriPrefix = "/nausf-sorprotection/v1"
	AusfAuthResUriPrefix          = "/nausf-auth/v1"
	AusfUpuprotectionResUriPrefix = "/nausf-upuprotection/v1"
)

type Config struct {
	Info          *Info          `yaml:"info" valid:"required"`
	Configuration *Configuration `yaml:"configuration" valid:"required"`
	Logger        *Logger        `yaml:"logger" valid:"required"`
	sync.RWMutex
}

func (c *Config) Validate() (bool, error) {
	if configuration := c.Configuration; configuration != nil {
		if result, err := configuration.validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Info struct {
	Version     string `yaml:"version,omitempty" valid:"required,in(1.0.3)"`
	Description string `yaml:"description,omitempty" valid:"type(string)"`
}

type Configuration struct {
	Sbi                  *Sbi            `yaml:"sbi,omitempty" valid:"required"`
	ServiceNameList      []string        `yaml:"serviceNameList,omitempty" valid:"required"`
	NrfUri               string          `yaml:"nrfUri,omitempty" valid:"url,required"`
	PlmnSupportList      []models.PlmnId `yaml:"plmnSupportList,omitempty" valid:"required"`
	GroupId              string          `yaml:"groupId,omitempty" valid:"type(string),minstringlength(1)"`
	EapAkaSupiImsiPrefix bool            `yaml:"eapAkaSupiImsiPrefix,omitempty" valid:"type(bool),optional"`
}

type Logger struct {
	Enable       bool   `yaml:"enable" valid:"type(bool)"`
	Level        string `yaml:"level" valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"type(bool)"`
}

func (c *Configuration) validate() (bool, error) {
	if sbi := c.Sbi; sbi != nil {
		if result, err := sbi.validate(); err != nil {
			return result, err
		}
	}

	for index, serviceName := range c.ServiceNameList {
		switch {
		case serviceName == "nausf-auth":
		default:
			err := errors.New("Invalid serviceNameList[" + strconv.Itoa(index) + "]: " +
				serviceName + ", should be nausf-auth.")
			return false, err
		}
	}

	for index, plmnId := range c.PlmnSupportList {
		if result := govalidator.StringMatches(plmnId.Mcc, "^[0-9]{3}$"); !result {
			err := errors.New("Invalid plmnSupportList[" + strconv.Itoa(index) + "].Mcc: " +
				plmnId.Mcc + ", should be 3 digits interger.")
			return false, err
		}

		if result := govalidator.StringMatches(plmnId.Mnc, "^[0-9]{2,3}$"); !result {
			err := errors.New("Invalid plmnSupportList[" + strconv.Itoa(index) + "].Mnc: " +
				plmnId.Mnc + ", should be 2 or 3 digits interger.")
			return false, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

type Sbi struct {
	Scheme       string `yaml:"scheme" valid:"scheme"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty" valid:"host,required"` // IP that is registered at NRF.
	BindingIPv4  string `yaml:"bindingIPv4,omitempty" valid:"host,required"`  // IP used to run the server in the node.
	Port         int    `yaml:"port,omitempty" valid:"port,required"`
	Tls          *Tls   `yaml:"tls,omitempty" valid:"optional"`
}

func (s *Sbi) validate() (bool, error) {
	govalidator.TagMap["scheme"] = govalidator.Validator(func(str string) bool {
		return str == "https" || str == "http"
	})

	if tls := s.Tls; tls != nil {
		if result, err := tls.validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(s)
	return result, appendInvalid(err)
}

type Tls struct {
	Pem string `yaml:"pem,omitempty" valid:"type(string),minstringlength(1),required"`
	Key string `yaml:"key,omitempty" valid:"type(string),minstringlength(1),required"`
}

func (t *Tls) validate() (bool, error) {
	result, err := govalidator.ValidateStruct(t)
	return result, err
}

func appendInvalid(err error) error {
	var errs govalidator.Errors

	if err == nil {
		return nil
	}

	es := err.(govalidator.Errors).Errors()
	for _, e := range es {
		errs = append(errs, fmt.Errorf("Invalid %w", e))
	}

	return error(errs)
}

func (c *Config) GetVersion() string {
	c.RLock()
	defer c.RUnlock()

	if c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}

func (c *Config) SetLogEnable(enable bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Enable: enable,
			Level:  "info",
		}
	} else {
		c.Logger.Enable = enable
	}
}

func (c *Config) SetLogLevel(level string) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Level: level,
		}
	} else {
		c.Logger.Level = level
	}
}

func (c *Config) SetLogReportCaller(reportCaller bool) {
	c.Lock()
	defer c.Unlock()

	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{
			Level:        "info",
			ReportCaller: reportCaller,
		}
	} else {
		c.Logger.ReportCaller = reportCaller
	}
}

func (c *Config) GetLogEnable() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.Enable
}

func (c *Config) GetLogLevel() string {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return "info"
	}
	return c.Logger.Level
}

func (c *Config) GetLogReportCaller() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.ReportCaller
}
