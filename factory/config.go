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
	Scheme       string `yaml:"scheme"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty"` // IP that is registered at NRF.
	// IPv6Addr string `yaml:"ipv6Addr,omitempty"`
	BindingIPv4 string `yaml:"bindingIPv4,omitempty"` // IP used to run the server in the node.
	Port        int    `yaml:"port,omitempty"`
}

type Security struct {
	IntegrityOrder []string `yaml:"integrityOrder,omitempty"`
	CipheringOrder []string `yaml:"cipheringOrder,omitempty"`
}
