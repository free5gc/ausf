package producer

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/stretchr/testify/assert"
	"testing"
)

type testEAPAKAPrimeCase struct {
	Identity    string `json:"Identity"`
	NetworkName string `json:"Networkname"`
	RAND        string `json:"RAND"`
	AUTN        string `json:"AUTN"`
	IK          string `json:"IK"`
	CK          string `json:"CK"`
	RES         string `json:"RES"`
	CKPrime     string `json:"CKPrime"`
	IKPrime     string `json:"IKPrime"`
	K_encr      string `json:"K_encr"`
	K_aut       string `json:"K_aut"`
	K_re        string `json:"K_re"`
	MSK         string `json:"MSK"`
	EMSK        string `json:"EMSK"`
}

func TestEAPAKAPrimePrf(t *testing.T) {
	testcases := []string{"testcase1.json", "testcase2.json", "testcase3.json", "testcase4.json"}
	for _, testfile := range testcases {
		jsonFile, _ := os.Open(testfile)
		byteValue, _ := ioutil.ReadAll(jsonFile)
		var testData testEAPAKAPrimeCase
		json.Unmarshal(byteValue, &testData)

		K_encr, K_aut, K_re, MSK, EMSK := eapAkaPrimePrf(testData.IKPrime, testData.CKPrime, testData.Identity)
		assert.True(t, testData.K_encr == K_encr)
		assert.True(t, testData.K_aut == K_aut)
		assert.True(t, testData.K_re == K_re)
		assert.True(t, testData.MSK == MSK)
		assert.True(t, testData.EMSK == EMSK)
	}
}
