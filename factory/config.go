/*
 * AUSF Configuration Factory
 */

package factory

import "free5gc/lib/openapi/models"

type Config struct {
	Info *Info `yaml:"info"`

	Configuration *Configuration `yaml:"configuration"`
}

type Info struct {
	Version string `yaml:"version,omitempty"`

	Description string `yaml:"description,omitempty"`
}

type Configuration struct {
	Sbi *Sbi `yaml:"sbi,omitempty"`

	ServiceNameList []string `yaml:"serviceNameList,omitempty"`

	NrfUri string `yaml:"nrfUri,omitempty"`

	PlmnSupportList []models.PlmnId `yaml:"plmnSupportList,omitempty"`

	GroupId string `yaml:"groupId,omitempty"`
}

type Sbi struct {
	Scheme   string `yaml:"scheme"`
	IPv4Addr string `yaml:"ipv4Addr,omitempty"`
	// IPv6Addr string `yaml:"ipv6Addr,omitempty"`
	Port int `yaml:"port,omitempty"`
}

type Security struct {
	IntegrityOrder []string `yaml:"integrityOrder,omitempty"`
	CipheringOrder []string `yaml:"cipheringOrder,omitempty"`
}
