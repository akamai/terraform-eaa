package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v6/pkg/edgegrid"
)

var (
	ErrInvalidArgument = errors.New("invalid arguments provided")
	ErrMarshaling      = errors.New("marshaling input")
	ErrUnmarshaling    = errors.New("unmarshaling output")
)

const (
	MGMT_POP_URL = "crux/v1/mgmt-pop"
	APPS_URL     = "crux/v1/mgmt-pop/apps"
)

const (
	APP_TYPE_ENTERPRISE_HOSTED = 1
	APP_TYPE_SAAS              = 2
	APP_TYPE_BOOKMARK          = 3
	APP_TYPE_TUNNEL            = 4
	APP_TYPE_ETP               = 5
)

type EaaClient struct {
	ContractID       string
	AccountSwitchKey string
	Client           *http.Client
	Signer           edgegrid.Signer
	Host             string
}

type AppsResponse struct {
	Meta struct {
		TotalCount int `json:"total_count"`
	} `json:"meta"`
	Applications []Application `json:"objects"`
}

type Server struct {
	OriginHost     string `json:"origin_host"`
	OrigTLS        bool   `json:"orig_tls"`
	OriginPort     int    `json:"origin_port"`
	OriginProtocol string `json:"origin_protocol"`
}

type TunnelInternalHost struct {
	Host      string `json:"host"`
	PortRange string `json:"port_range"`
	ProtoType int    `json:"proto_type"`
}

type Application struct {
	Name          string  `json:"name"`
	Description   *string `json:"description"`
	AppProfile    int     `json:"app_profile"`
	AppType       int     `json:"app_type"`
	ClientAppMode int     `json:"client_app_mode"`

	Host        *string `json:"host"`
	BookmarkURL string  `json:"bookmark_url"`
	AppLogo     *string `json:"app_logo"`

	OrigTLS             string               `json:"orig_tls"`
	OriginHost          *string              `json:"origin_host"`
	OriginPort          int                  `json:"origin_port"`
	TunnelInternalHosts []TunnelInternalHost `json:"tunnel_internal_hosts"`
	Servers             []Server             `json:"servers"`

	POP       string `json:"pop"`
	POPName   string `json:"popName"`
	POPRegion string `json:"popRegion"`

	AuthType    int     `json:"auth_type"`
	Cert        *string `json:"cert"`
	AuthEnabled string  `json:"auth_enabled"`
	SSLCACert   string  `json:"ssl_ca_cert"`

	AppDeployed    bool    `json:"app_deployed"`
	AppOperational int     `json:"app_operational"`
	AppStatus      int     `json:"app_status"`
	CName          *string `json:"cname"`
	Status         int     `json:"status"`

	AdvancedSettings AdvancedSettings `json:"advanced_settings"`

	UUIDURL string `json:"uuid_url"`
}

type AdvancedSettings struct {
	IsSSLVerificationEnabled  string  `json:"is_ssl_verification_enabled,omitempty"`
	IgnoreCnameResolution     string  `json:"ignore_cname_resolution,omitempty"`
	EdgeAuthenticationEnabled string  `json:"edge_authentication_enabled,omitempty"`
	G2OEnabled                string  `json:"g2o_enabled,omitempty"`
	G2ONonce                  *string `json:"g2o_nonce,omitempty"`
	G2OKey                    *string `json:"g2o_key,omitempty"`
	XWappReadTimeout          string  `json:"x_wapp_read_timeout,omitempty"`
	InternalHostname          *string `json:"internal_hostname,omitempty"`
	InternalHostPort          string  `json:"internal_host_port,omitempty"`
	WildcardInternalHostname  string  `json:"wildcard_internal_hostname,omitempty"`
	IPAccessAllow             string  `json:"ip_access_allow,omitempty"`
}

func main() {
	var contractID string
	var accountSwitch string
	var appNames string

	fmt.Println("Enter Your Contract Id: ")
	_, err := fmt.Scanln(&contractID)
	if err != nil {
		fmt.Println("Error reading contractID:", err)
		return
	}
	fmt.Println("Enter Your accountSwitchKey: ")
	_, err = fmt.Scanln(&accountSwitch)
	if err != nil {
		fmt.Println("Error reading accountSwitch:", err)
		return
	}

	fmt.Println("Enter comma seperated app names: (example: exampleapp, *app, app*, ex*app)")
	_, err = fmt.Scanln(&appNames)
	if err != nil {
		fmt.Println("Error reading appNames:", err)
		return
	}
	edgerc, err := edgegrid.New(edgegrid.WithFile(".edgerc"))
	if err != nil {
		fmt.Println("EdgeRc error")
	}

	eaaClient := &EaaClient{
		Client:           http.DefaultClient,
		ContractID:       contractID,
		Signer:           edgerc,
		AccountSwitchKey: accountSwitch,
		Host:             edgerc.Host,
	}
	err = GenerateConfiguration(eaaClient, appNames)
	if err != nil {
		fmt.Println(err)
	}

}

func GenerateConfiguration(ec *EaaClient, appNames string) error {
	apiURL := fmt.Sprintf("https://%s/%s", ec.Host, APPS_URL)
	appsResponse := AppsResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &appsResponse, false)
	if err != nil {
		return err
	}
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
		fmt.Println("get apps failed")
		return err
	}

	file, err := os.Create("import_existing_apps.tf")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return err
	}

	defer file.Close()
	terraformBlock := fmt.Sprintf(`terraform {
		required_providers {
		  eaa = {
			source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
			version = "1.0.0"
		  }
		}
	  }

	  provider "eaa" {
		contractid       = "%s"
		edgerc           = ".edgerc"
	  }


	  `, ec.ContractID)

	// Write the Terraform configuration block to the file
	_, err = file.WriteString(terraformBlock)
	if err != nil {
		fmt.Println("Error writing to tf config :", err)
		return err
	}
	appList := strings.Split(strings.ToLower(appNames), ",")
	for _, pattern := range appList {
		for _, app := range appsResponse.Applications {
			if app.Name == "" || app.UUIDURL == "" || !(app.AppType == APP_TYPE_ENTERPRISE_HOSTED || app.AppType == APP_TYPE_TUNNEL) {
				continue
			}

			if pattern != "" && matchesPattern(strings.ToLower(app.Name), pattern) {
				replacedString := strings.ReplaceAll(app.Name, " ", "_")

				appName := fmt.Sprintf("eaa_application.%s", replacedString)
				generateImportBlock(file, app.UUIDURL, appName)
			}

		}
	}
	return nil
}

func generateImportBlock(file *os.File, resourceID, resourceType string) {
	importBlock := fmt.Sprintf("import {\n  to = %s\n  id = \"%s\"\n}\n\n", resourceType, resourceID)
	_, err := file.WriteString(importBlock)
	if err != nil {
		fmt.Println("Error writing to file:", err)
	}
}

func matchesPattern(s, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		return strings.Contains(s, pattern[1:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(s, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	if strings.Contains(pattern, "*") {
		// Split the pattern into two parts at the asterisk
		parts := strings.Split(pattern, "*")
		// Check if the string starts with the first part and ends with the second part
		return strings.HasPrefix(s, parts[0]) && strings.HasSuffix(s, parts[1])
	}
	return s == pattern
}

// Exec will sign and execute the request using the client edgegrid.Config
func (ec *EaaClient) SendAPIRequest(apiURL string, method string, in interface{}, out interface{}, global bool) (*http.Response, error) {
	if !global {
		queryParams := url.Values{}
		if ec.ContractID != "" {
			queryParams.Set("contractId", ec.ContractID)
		}
		if ec.AccountSwitchKey != "" {
			queryParams.Set("accountSwitchKey", ec.AccountSwitchKey)
		}
		if method == http.MethodGet {
			queryParams.Set("expand", "true")
			queryParams.Set("limit", "0")
		}
		apiURL = fmt.Sprintf("%s?%s", apiURL, queryParams.Encode())
	}

	r, _ := http.NewRequest(method, apiURL, nil)
	r.Header.Set("Content-Type", "application/json")

	r.URL.RawQuery = r.URL.Query().Encode()
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrMarshaling, err)
		}

		r.Body = io.NopCloser(bytes.NewBuffer(data))
		r.ContentLength = int64(len(data))
	}
	ec.Signer.SignRequest(r)

	resp, err := ec.Client.Do(r)
	if err != nil {
		return nil, err
	}
	if out != nil &&
		resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices &&
		resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusResetContent {
		data, err := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewBuffer(data))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, out); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrUnmarshaling, err)
		}
	}

	return resp, nil
}
