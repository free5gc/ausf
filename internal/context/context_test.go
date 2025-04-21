package context

import (
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/free5gc/ausf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

func createConfigFile(t *testing.T, postContent []byte) *os.File {
	content := []byte(`info:
  version: "1.0.4"

logger:
  level: debug
`)

	configFile, err := os.CreateTemp("", "")
	if err != nil {
		t.Errorf("can't create temp file: %+v", err)
	}

	if _, err := configFile.Write(content); err != nil {
		t.Errorf("can't write content of temp file: %+v", err)
	}
	if _, err := configFile.Write(postContent); err != nil {
		t.Errorf("can't write content of temp file: %+v", err)
	}
	if err := configFile.Close(); err != nil {
		t.Fatal(err)
	}
	return configFile
}

func TestInitAusfContextWithConfigIPv6(t *testing.T) {
	postContent := []byte(`configuration:
  serviceNameList:
    - nausf-auth
  plmnSupportList:
    - mcc: 208
      mnc: 93
  sbi:
    scheme: http
    registerIP: "2001:db8::1:0:0:13"
    bindingIP: "2001:db8::1:0:0:13"
    port: 8313
  nrfUri: http://127.0.0.10:8000`)

	configFile := createConfigFile(t, postContent)

	// Test the initialization with the config file
	cfg, err := factory.ReadConfig(configFile.Name())
	if err != nil {
		t.Errorf("invalid read config: %+v %+v", err, cfg)
	}
	factory.AusfConfig = cfg

	GetSelf().NfService = make(map[models.ServiceName]models.NrfNfManagementNfService)
	InitAusfContext(GetSelf())

	assert.Equal(t, ausfContext.SBIPort, 8313)
	assert.Equal(t, ausfContext.RegisterIP.String(), "2001:db8::1:0:0:13")
	assert.Equal(t, ausfContext.BindingIP.String(), "2001:db8::1:0:0:13")
	assert.Equal(t, ausfContext.UriScheme, models.UriScheme("http"))

	// Close the config file
	t.Cleanup(func() {
		if err := os.RemoveAll(configFile.Name()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInitAusfContextWithConfigIPv4(t *testing.T) {
	postContent := []byte(`configuration:
  serviceNameList:
    - nausf-auth
  plmnSupportList:
    - mcc: 208
      mnc: 93
  sbi:
    scheme: http
    registerIP: "127.0.0.13"
    bindingIP: "127.0.0.13"
    port: 8131
  nrfUri: http://127.0.0.10:8000`)

	configFile := createConfigFile(t, postContent)

	// Test the initialization with the config file
	cfg, err := factory.ReadConfig(configFile.Name())
	if err != nil {
		t.Errorf("invalid read config: %+v %+v", err, cfg)
	}
	factory.AusfConfig = cfg

	GetSelf().NfService = make(map[models.ServiceName]models.NrfNfManagementNfService)
	InitAusfContext(GetSelf())

	assert.Equal(t, ausfContext.SBIPort, 8131)
	assert.Equal(t, ausfContext.RegisterIP.String(), "127.0.0.13")
	assert.Equal(t, ausfContext.BindingIP.String(), "127.0.0.13")
	assert.Equal(t, ausfContext.UriScheme, models.UriScheme("http"))

	// Close the config file
	t.Cleanup(func() {
		if err := os.RemoveAll(configFile.Name()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInitAusfContextWithConfigDeprecated(t *testing.T) {
	postContent := []byte(`configuration:
  serviceNameList:
    - nausf-auth
  plmnSupportList:
    - mcc: 208
      mnc: 93
  sbi:
    scheme: http
    registerIPv4: "127.0.0.30"
    bindingIPv4: "127.0.0.30"
    port: 8003
  nrfUri: http://127.0.0.10:8000`)

	configFile := createConfigFile(t, postContent)

	// Test the initialization with the config file
	cfg, err := factory.ReadConfig(configFile.Name())
	if err != nil {
		t.Errorf("invalid read config: %+v %+v", err, cfg)
	}
	factory.AusfConfig = cfg

	GetSelf().NfService = make(map[models.ServiceName]models.NrfNfManagementNfService)
	InitAusfContext(GetSelf())

	assert.Equal(t, ausfContext.SBIPort, 8003)
	assert.Equal(t, ausfContext.RegisterIP.String(), "127.0.0.30")
	assert.Equal(t, ausfContext.BindingIP.String(), "127.0.0.30")
	assert.Equal(t, ausfContext.UriScheme, models.UriScheme("http"))

	// Close the config file
	t.Cleanup(func() {
		if err := os.RemoveAll(configFile.Name()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInitAusfContextWithConfigEmptySBI(t *testing.T) {
	postContent := []byte(`configuration:
  serviceNameList:
    - nausf-auth
  plmnSupportList:
    - mcc: 208
      mnc: 93
  nrfUri: http://127.0.0.10:8000`)

	configFile := createConfigFile(t, postContent)

	// Test the initialization with the config file fails
	_, err := factory.ReadConfig(configFile.Name())
	assert.Equal(t, err, errors.New("Config validate Error"))

	// Close the config file
	t.Cleanup(func() {
		if err := os.RemoveAll(configFile.Name()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInitAusfContextWithConfigMissingRegisterIP(t *testing.T) {
	postContent := []byte(`configuration:
  serviceNameList:
    - nausf-auth
  plmnSupportList:
    - mcc: 208
      mnc: 93
  sbi:
    bindingIP: "2001:db8::1:0:0:130"
  serviceNameList:
    - nudm-sdm
  nrfUri: http://127.0.0.10:8000`)

	configFile := createConfigFile(t, postContent)

	// Test the initialization with the config file
	cfg, err := factory.ReadConfig(configFile.Name())
	if err != nil {
		t.Errorf("invalid read config: %+v %+v", err, cfg)
	}
	factory.AusfConfig = cfg

	GetSelf().NfService = make(map[models.ServiceName]models.NrfNfManagementNfService)
	InitAusfContext(GetSelf())

	assert.Equal(t, ausfContext.SBIPort, 8000)
	assert.Equal(t, ausfContext.BindingIP.String(), "2001:db8::1:0:0:130")
	assert.Equal(t, ausfContext.RegisterIP.String(), "2001:db8::1:0:0:130")
	assert.Equal(t, ausfContext.UriScheme, models.UriScheme("https"))

	// Close the config file
	t.Cleanup(func() {
		if err := os.RemoveAll(configFile.Name()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInitAusfContextWithConfigMissingBindingIP(t *testing.T) {
	postContent := []byte(`configuration:
  serviceNameList:
    - nausf-auth
  plmnSupportList:
    - mcc: 208
      mnc: 93
  sbi:
    registerIP: "2001:db8::1:0:0:131"
  serviceNameList:
    - nudm-sdm
  nrfUri: http://127.0.0.10:8000`)

	configFile := createConfigFile(t, postContent)

	// Test the initialization with the config file
	cfg, err := factory.ReadConfig(configFile.Name())
	if err != nil {
		t.Errorf("invalid read config: %+v %+v", err, cfg)
	}
	factory.AusfConfig = cfg

	GetSelf().NfService = make(map[models.ServiceName]models.NrfNfManagementNfService)
	InitAusfContext(GetSelf())

	assert.Equal(t, ausfContext.SBIPort, 8000)
	assert.Equal(t, ausfContext.BindingIP.String(), "2001:db8::1:0:0:131")
	assert.Equal(t, ausfContext.RegisterIP.String(), "2001:db8::1:0:0:131")
	assert.Equal(t, ausfContext.UriScheme, models.UriScheme("https"))

	// Close the config file
	t.Cleanup(func() {
		if err := os.RemoveAll(configFile.Name()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInitAusfContextWithConfigIPv6FromEnv(t *testing.T) {
	postContent := []byte(`configuration:
  serviceNameList:
    - nudm-sdm
  plmnSupportList:
    - mcc: 208
      mnc: 93
  sbi:
    scheme: http
    registerIP: "MY_REGISTER_IP"
    bindingIP: "MY_BINDING_IP"
    port: 8313
  nrfUri: http://127.0.0.10:8000`)

	configFile := createConfigFile(t, postContent)

	if err := os.Setenv("MY_REGISTER_IP", "2001:db8::1:0:0:130"); err != nil {
		t.Errorf("Can't set MY_BINDING_IP variable environnement: %+v", err)
	}
	if err := os.Setenv("MY_BINDING_IP", "2001:db8::1:0:0:130"); err != nil {
		t.Errorf("Can't set MY_BINDING_IP variable environnement: %+v", err)
	}

	// Test the initialization with the config file
	cfg, err := factory.ReadConfig(configFile.Name())
	if err != nil {
		t.Errorf("invalid read config: %+v %+v", err, cfg)
	}
	factory.AusfConfig = cfg

	GetSelf().NfService = make(map[models.ServiceName]models.NrfNfManagementNfService)
	InitAusfContext(GetSelf())

	assert.Equal(t, ausfContext.SBIPort, 8313)
	assert.Equal(t, ausfContext.RegisterIP.String(), "2001:db8::1:0:0:130")
	assert.Equal(t, ausfContext.BindingIP.String(), "2001:db8::1:0:0:130")
	assert.Equal(t, ausfContext.UriScheme, models.UriScheme("http"))

	// Close the config file
	t.Cleanup(func() {
		if err := os.RemoveAll(configFile.Name()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestResolveIPLocalhost(t *testing.T) {
	expectedAddr, err := netip.ParseAddr("::1")
	if err != nil {
		t.Errorf("invalid expected IP: %+v", expectedAddr)
	}

	addr := resolveIP("localhost")
	if addr != expectedAddr {
		t.Errorf("invalid IP: %+v", addr)
	}
	assert.Equal(t, addr, expectedAddr)
}

func TestResolveIPv4(t *testing.T) {
	expectedAddr, err := netip.ParseAddr("127.0.0.1")
	if err != nil {
		t.Errorf("invalid expected IP: %+v", expectedAddr)
	}

	addr := resolveIP("127.0.0.1")
	if addr != expectedAddr {
		t.Errorf("invalid IP: %+v", addr)
	}
}

func TestResolveIPv6(t *testing.T) {
	expectedAddr, err := netip.ParseAddr("2001:db8::1:0:0:1")
	if err != nil {
		t.Errorf("invalid expected IP: %+v", expectedAddr)
	}

	addr := resolveIP("2001:db8::1:0:0:1")
	if addr != expectedAddr {
		t.Errorf("invalid IP: %+v", addr)
	}
}
