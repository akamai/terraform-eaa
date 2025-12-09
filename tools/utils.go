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
	"regexp"
	"strings"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v6/pkg/edgegrid"
)

const (
	generate_info = "The config file `import_existing_apps.tf` with import blocks is generated.\n" +
		"1. To generate the configuration, run the following command:\n" +
		"   terraform plan -generate-config-out=generated_resources.tf\n" +
		"2. In the resultant resources configuration file, add the provider section\n" +
		"   with the EAA provider-specific configuration, before modifying and applying the resource configuration.\n"
)

const (
	MGMT_POP_URL = "crux/v3/mgmt-pop"
	APPS_URL     = "crux/v3/mgmt-pop/apps"
)

const (
	APP_TYPE_ENTERPRISE_HOSTED = 1
	APP_TYPE_SAAS              = 2
	APP_TYPE_BOOKMARK          = 3
	APP_TYPE_TUNNEL            = 4
	APP_TYPE_ETP               = 5
)

var (
	ErrInvalidArgument = errors.New("invalid arguments provided")
	ErrMarshaling      = errors.New("error marshaling input")
	ErrUnmarshaling    = errors.New("error unmarshaling output")
	ErrGetApp          = errors.New("error retrieving applications")
)

type ErrorResponse struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Instance  string `json:"instance"`
	Detail    string `json:"detail"`
	ProblemID string `json:"problemId"`
}

type Meta struct {
	Next       *string `json:"next,omitempty"`
	Previous   *string `json:"previous,omitempty"`
	Limit      int     `json:"limit,omitempty"`
	Offset     int     `json:"offset,omitempty"`
	TotalCount int     `json:"total_count,omitempty"`
}

type AppsResponse struct {
	Applications []Application `json:"objects"`
	Metadata     Meta          `json:"meta"`
}

type Application struct {
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
}

type importBlock struct {
	appID   string
	appName string
}

type EaaClient struct {
	ContractID       string
	AccountSwitchKey string
	Client           *http.Client
	Signer           edgegrid.Signer
	Host             string
}

// SendAPIRequest will sign and execute the request using the client edgegrid.Config
func (ec *EaaClient) SendAPIRequest(apiURL string, method string, in interface{}, out interface{}, global bool) (*http.Response, error) {
	if !global {
		parsedURL, err := url.Parse(apiURL)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrMarshaling, err)
		}
		queryParams := parsedURL.Query()
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
		parsedURL.RawQuery = queryParams.Encode()

		apiURL = parsedURL.String()

	}

	fmt.Println(apiURL)
	r, _ := http.NewRequest(method, apiURL, http.NoBody)
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

func FormatErrorResponse(errResp *http.Response) (string, error) {
	var errResponse ErrorResponse
	data, err := io.ReadAll(errResp.Body)

	if err == nil {
		err := json.Unmarshal(data, &errResponse)
		if err != nil {
			return "", ErrUnmarshaling
		}
		return errResponse.Detail, nil
	}
	return "", ErrUnmarshaling
}

func writeProviderBlock(file *os.File, cid, ask, edgercPath string) error {
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
		accountswitchkey = "%s"
		edgerc           = "%s"
	  }

	  `, cid, ask, edgercPath)

	// Write the Terraform configuration block to the file
	_, err := file.WriteString(terraformBlock)
	if err != nil {
		fmt.Println("Error writing to tf config :", err)
		return err
	}
	return nil
}

func generateImportBlock(file *os.File, resourceID, resourceType string) error {
	importBlock := fmt.Sprintf("import {\n  to = %s\n  id = \"%s\"\n}\n\n", resourceType, resourceID)
	_, err := file.WriteString(importBlock)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return err
	}
	return nil
}

func matchesQueryString(pattern string) string {
	// Handle patterns that are only asterisks
	if pattern == "*" {
		return "name__icontains="
	}
	cleanedPattern := strings.ReplaceAll(pattern, "*", "")
	return fmt.Sprintf("name__icontains=%s", cleanedPattern)
}

func isLetter(r rune) bool {
	return r >= 'a' && r <= 'z'
}

func convertToValidTFName(appName string) string {
	tfName := strings.ToLower(appName)

	// replace invalid characters with underscores
	re := regexp.MustCompile(`[^a-z0-9]+`)
	tfName = re.ReplaceAllString(tfName, "_")
	tfName = strings.Trim(tfName, "_")

	if len(tfName) > 0 && !isLetter(rune(tfName[0])) {
		tfName = "a_" + tfName
	}

	return tfName
}
