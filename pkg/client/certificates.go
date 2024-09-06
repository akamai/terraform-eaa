package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrCertificatesGet = errors.New("certificates get failed")
	ErrCertNotExist    = errors.New("certificate does not exist ")
)

type CreateSelfSignedCertRequest struct {
	HostName string `json:"host_name"`
	CertType int    `json:"cert_type"`
}

func (sscert *CreateSelfSignedCertRequest) CreateSelfSignedCertificate(ctx context.Context, ec *EaaClient) (*CertificateResponse, error) {
	logger := ec.Logger
	if sscert.HostName == "" {
		logger.Error("create self signed cert failed. hostname is invalid")
		return nil, ErrInvalidType
	}
	sscert.CertType = CERT_TYPE_APP_SSC

	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, CERTIFICATES_URL)

	var ssCertResp CertificateResponse
	ssCertHttpResp, err := ec.SendAPIRequest(apiURL, "POST", sscert, &ssCertResp, false)
	if err != nil {
		ec.Logger.Error("self certificate generation request failed. err: ", err)
		return nil, err
	}
	if !(ssCertHttpResp.StatusCode >= http.StatusOK && ssCertHttpResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(ssCertHttpResp)
		ssCertErrMsg := fmt.Errorf("%w: %s", ErrAppUpdate, desc)

		ec.Logger.Error("self signed certificate generation failed. ssCertHttpResp.StatusCode: desc: ", ssCertHttpResp.StatusCode, desc)
		return nil, ssCertErrMsg
	}
	return &ssCertResp, nil
}

type CertificateResponse struct {
	AppCount    int     `json:"app_count,omitempty"`
	Cert        string  `json:"cert,omitempty"`
	CertType    int     `json:"cert_type,omitempty"`
	CertFile    *string `json:"cert_file_name,omitempty"` // Assuming it could be null
	CN          string  `json:"cn,omitempty"`
	CreatedAt   string  `json:"created_at,omitempty"`
	DaysLeft    int     `json:"days_left,omitempty"`
	Description *string `json:"description,omitempty"` // Assuming it could be null
	DirCount    int     `json:"dir_count,omitempty"`
	ExpiredAt   string  `json:"expired_at,omitempty"`
	HostName    string  `json:"host_name,omitempty"`
	IssuedAt    string  `json:"issued_at,omitempty"`
	Issuer      string  `json:"issuer,omitempty"`
	ModifiedAt  string  `json:"modified_at,omitempty"`
	Name        string  `json:"name,omitempty"`
	Resource    string  `json:"resource,omitempty"`
	Status      int     `json:"status,omitempty"`
	Subject     string  `json:"subject,omitempty"`
	Uploaded    *string `json:"uploaded,omitempty"`
	UUIDURL     string  `json:"uuid_url,omitempty"`
}

type CertObject struct {
	Name      string `json:"name"`
	UUIDURL   string `json:"uuid_url"`
	CertType  int    `json:"cert_type"`
	ExpiredAt string `json:"expired_at"`
	CreatedAt string `json:"created_at"`
}

type CertsResponse struct {
	Objects []CertObject `json:"objects"`
}

func GetCertificates(ec *EaaClient) ([]CertObject, error) {
	apiURL := fmt.Sprintf("%s://%s/%s/thin", URL_SCHEME, ec.Host, CERTIFICATES_URL)
	certsResponse := CertsResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &certsResponse, false)
	if err != nil {
		return nil, err
	}
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(getResp)
		updErrMsg := fmt.Errorf("%w: %s", ErrCertificatesGet, desc)
		return nil, updErrMsg
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

func DoesSelfSignedCertExistForHost(ec *EaaClient, host string) (*CertObject, error) {
	certs, err := GetCertificates(ec)
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

func GetCertificate(ec *EaaClient, cert_uuid_url string) (*CertificateResponse, error) {
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, CERTIFICATES_URL, cert_uuid_url)
	certResponse := CertificateResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &certResponse, false)
	if err != nil {
		return nil, err
	}
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(getResp)
		updErrMsg := fmt.Errorf("%w: %s", ErrCertificatesGet, desc)
		return nil, updErrMsg
	}
	return &certResponse, nil
}

func DoesUploadedCertExist(ec *EaaClient, host string) (*CertObject, error) {
	certs, err := GetCertificates(ec)
	if err != nil {
		return nil, err
	}
	for _, cert := range certs {
		if cert.Name == host && cert.CertType != CERT_TYPE_APP_SSC && cert.CertType != CERT_TYPE_CA {
			return &cert, nil
		}
	}
	return nil, ErrCertNotExist
}
