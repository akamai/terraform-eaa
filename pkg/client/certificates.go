package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type CreateSelfSignedCertRequest struct {
	HostName string `json:"host_name"`
	CertType int    `json:"cert_type"`
}

type CreateAppCertRequest struct {
	Name       string `json:"name"`
	Cert       string `json:"cert"`
	PrivateKey string `json:"private_key"`
	Password   string `json:"password"`
	CertType   int    `json:"cert_type"`
}

type UpdateAppCertRequest struct {
	UUIDURL    string `json:"uuid_url"`
	Name       string `json:"name"`
	Cert       string `json:"cert"`
	PrivateKey string `json:"private_key"`
	Password   string `json:"password"`
	CertType   int    `json:"cert_type"`
}

type CertThinObject struct {
	Name       string `json:"name"`
	UUIDURL    string `json:"uuid_url"`
	CertType   int    `json:"cert_type"`
	Associated bool   `json:"associated"`
}

type CertThinResponse struct {
	Objects []CertThinObject `json:"objects"`
}

func (sscert *CreateSelfSignedCertRequest) CreateSelfSignedCertificate(ctx context.Context, ec *EaaClient) (*CertificateResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagCreate}

	if sscert.HostName == "" {
		logging.Warn(ctx, "create self signed cert failed: hostname is invalid", tags)
		return nil, ErrInvalidType
	}
	sscert.CertType = CERT_TYPE_APP_SSC

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, CERTIFICATES_URL)

	var ssCertResp CertificateResponse
	ssCertHTTPResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", sscert, &ssCertResp, false)
	if err != nil {
		return nil, err
	}
	if ssCertHTTPResp.StatusCode < http.StatusOK || ssCertHTTPResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(ssCertHTTPResp)
		logging.Error(ctx, "self signed certificate generation failed", tags, map[string]any{"status": ssCertHTTPResp.StatusCode, "description": desc})
		return nil, logging.Errorf(tags, "self signed certificate generation failed: %s", desc)
	}
	return &ssCertResp, nil
}

type CertificateResponse struct {
	CertFile    *string     `json:"cert_file_name,omitempty"`
	Uploaded    interface{} `json:"uploaded,omitempty"`
	Description *string     `json:"description,omitempty"`
	HostName    string      `json:"host_name,omitempty"`
	Resource    string      `json:"resource,omitempty"`
	CreatedAt   string      `json:"created_at,omitempty"`
	UUIDURL     string      `json:"uuid_url,omitempty"`
	Cert        string      `json:"cert,omitempty"`
	CN          string      `json:"cn,omitempty"`
	ExpiredAt   string      `json:"expired_at,omitempty"`
	Subject     string      `json:"subject,omitempty"`
	IssuedAt    string      `json:"issued_at,omitempty"`
	Issuer      string      `json:"issuer,omitempty"`
	ModifiedAt  string      `json:"modified_at,omitempty"`
	Name        string      `json:"name,omitempty"`
	DirCount    int         `json:"dir_count,omitempty"`
	Status      int         `json:"status,omitempty"`
	AppCount    int         `json:"app_count,omitempty"`
	CertType    int         `json:"cert_type,omitempty"`
	DaysLeft    int         `json:"days_left,omitempty"`
}

type CertObject struct {
	Name      string `json:"name"`
	UUIDURL   string `json:"uuid_url"`
	ExpiredAt string `json:"expired_at"`
	CreatedAt string `json:"created_at"`
	CertType  int    `json:"cert_type"`
}

type AssociatedObject struct {
	Name    string `json:"name"`
	UUIDURL string `json:"uuid_url"`
	Status  int    `json:"app_status,omitempty"`
}

type CertificateExpandedResponse struct {
	Apps                   []AssociatedObject `json:"apps"`
	IDPs                   []AssociatedObject `json:"idps"`
	CertIDPs               []AssociatedObject `json:"cert_idps"`
	ClientCertIDPs         []AssociatedObject `json:"client_cert_idps"`
	SAMLCertIDPs           []AssociatedObject `json:"saml_cert_idps"`
	SAMLCustomSignCertIDPs []AssociatedObject `json:"saml_custom_sign_cert_idps"`
	CertificateResponse
}

type CertsResponse struct {
	Objects []CertObject `json:"objects"`
}

func GetCertificates(ctx context.Context, ec *EaaClient) ([]CertObject, error) {
	apiURL := fmt.Sprintf("%s://%s/%s/thin", URL_SCHEME, ec.Host, CERTIFICATES_URL)
	certsResponse := CertsResponse{}

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &certsResponse, false)
	if err != nil {
		return nil, err
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagRead}
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "certificates get failed: %s", desc)
	}

	var certs []CertObject
	for _, cert := range certsResponse.Objects {
		if cert.Name == "" || cert.UUIDURL == "" {
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func DoesSelfSignedCertExistForHost(ctx context.Context, ec *EaaClient, host string) (*CertObject, error) {
	certs, err := GetCertificates(ctx, ec)
	if err != nil {
		return nil, err
	}
	for _, cert := range certs {
		if cert.Name == host && cert.CertType == CERT_TYPE_APP_SSC {
			return &cert, nil
		}
	}
	return nil, nil
}

func GetCertificate(ctx context.Context, ec *EaaClient, certUUIDURL string) (*CertificateResponse, error) {
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, CERTIFICATES_URL, certUUIDURL)
	certResponse := CertificateResponse{}

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &certResponse, false)
	if err != nil {
		return nil, err
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagRead}
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "certificate get failed: %s", desc)
	}
	return &certResponse, nil
}

func DoesUploadedCertExist(ctx context.Context, ec *EaaClient, host string) (*CertObject, error) {
	certs, err := GetCertificates(ctx, ec)
	if err != nil {
		return nil, err
	}
	for _, cert := range certs {
		if cert.Name == host && cert.CertType != CERT_TYPE_APP_SSC && cert.CertType != CERT_TYPE_CA {
			return &cert, nil
		}
	}
	return nil, logging.Errorf([]logging.Tag{logging.TagAPI, logging.TagCert, logging.TagRead}, "uploaded certificate for host '%s' not found", host)
}

func GetCertificateExpanded(ctx context.Context, ec *EaaClient, certUUIDURL string) (*CertificateExpandedResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagRead}
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, CERTIFICATES_URL, certUUIDURL)
	var certResp CertificateExpandedResponse

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &certResp, false)
	if err != nil {
		return nil, err
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "certificate get failed: %s", desc)
	}
	return &certResp, nil
}

func DeleteCertificate(ctx context.Context, ec *EaaClient, certUUIDURL string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagDelete}
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, CERTIFICATES_URL, certUUIDURL)

	deleteResp, err := ec.SendAPIRequest(ctx, apiURL, http.MethodDelete, nil, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "certificate delete failed")
	}
	if deleteResp.StatusCode != http.StatusNoContent {
		desc := FormatErrorDescription(deleteResp)
		return logging.Errorf(tags, "certificate delete failed: %s", desc)
	}
	return nil
}

func GetCertificateAssociated(ctx context.Context, ec *EaaClient, certUUIDURL, certName string, certType int) (bool, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagRead}
	apiURL := fmt.Sprintf("%s://%s/%s/thin?cert_type=%d&search=%s",
		URL_SCHEME, ec.Host, CERTIFICATES_URL, certType, url.QueryEscape(certName))

	var thinResp CertThinResponse
	noExpand := false
	limit := 100
	opts := GetRequestOptions{Expand: &noExpand, Limit: &limit}
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &thinResp, false, opts)
	if err != nil {
		return false, logging.Wrapf(err, tags, "failed to check certificate association")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return false, logging.Errorf(tags, "failed to check certificate association: %s", desc)
	}

	for _, obj := range thinResp.Objects {
		if obj.UUIDURL == certUUIDURL {
			return obj.Associated, nil
		}
	}
	return false, nil
}

func CreateAppCertificate(ctx context.Context, ec *EaaClient, req *CreateAppCertRequest) (*CertificateResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagCreate}
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, CERTIFICATES_URL)

	var certResp CertificateResponse
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", req, &certResp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "create app certificate failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Errorf(tags, "create app certificate failed: %s", desc)
	}
	return &certResp, nil
}

func UpdateAppCertificate(ctx context.Context, ec *EaaClient, certUUIDURL string, req *UpdateAppCertRequest) (*CertificateResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagUpdate}
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, CERTIFICATES_URL, certUUIDURL)

	var certResp CertificateResponse
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "PUT", req, &certResp, false)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "update app certificate failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Errorf(tags, "update app certificate failed: %s", desc)
	}
	return &certResp, nil
}

func DeployCertificate(ctx context.Context, ec *EaaClient, certUUIDURL string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagUpdate}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/deploy", URL_SCHEME, ec.Host, CERTIFICATES_URL, certUUIDURL)

	emptyBody := struct{}{}
	httpResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", &emptyBody, nil, false)
	if err != nil {
		return logging.Wrapf(err, tags, "certificate deploy failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return logging.Errorf(tags, "certificate deploy failed: %s", desc)
	}
	return nil
}

func CreateCACertificate(ctx context.Context, ec *EaaClient, name, certContent, password string) (*CertificateResponse, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagCreate}
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, CERTIFICATES_URL)

	fields := map[string]string{
		"cert_type": strconv.Itoa(CERT_TYPE_CA),
		"name":      name,
		"password":  password,
	}

	httpResp, err := ec.SendMultipartRequest(ctx, apiURL, fields, "cert", []byte(certContent))
	if err != nil {
		return nil, logging.Wrapf(err, tags, "create CA certificate failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return nil, logging.Errorf(tags, "create CA certificate failed: %s", desc)
	}

	var certResp CertificateResponse
	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "failed to read create CA certificate response")
	}
	if err := json.Unmarshal(data, &certResp); err != nil {
		return nil, logging.Wrapf(err, tags, "failed to unmarshal create CA certificate response")
	}
	return &certResp, nil
}

func UpdateCACertificate(ctx context.Context, ec *EaaClient, certUUIDURL, name, certContent, password string) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagCert, logging.TagUpdate}
	apiURL := fmt.Sprintf("%s://%s/%s/%s/upload", URL_SCHEME, ec.Host, CERTIFICATES_URL, certUUIDURL)

	fields := map[string]string{
		"cert_type": strconv.Itoa(CERT_TYPE_CA),
		"name":      name,
		"password":  password,
	}

	httpResp, err := ec.SendMultipartRequest(ctx, apiURL, fields, "cert", []byte(certContent))
	if err != nil {
		return logging.Wrapf(err, tags, "update CA certificate failed")
	}
	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(httpResp)
		return logging.Errorf(tags, "update CA certificate failed: %s", desc)
	}
	return nil
}
