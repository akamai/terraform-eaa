package client

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrPopsGet = errors.New("Pops get failed")
)

type Pop struct {
	CreatedAt           string   `json:"created_at,omitempty"`
	Description         *string  `json:"description,omitempty"`
	Facility            string   `json:"facility,omitempty"`
	ModifiedAt          string   `json:"modified_at,omitempty"`
	Name                string   `json:"name,omitempty"`
	PopCategory         []string `json:"pop_category,omitempty"`
	PopType             string   `json:"pop_type,omitempty"`
	Region              string   `json:"region,omitempty"`
	RelatedFailoverPop  string   `json:"related_failover_pop,omitempty"`
	RelatedFailoverName string   `json:"related_failover_pop_name,omitempty"`
	ResourceURI         struct {
		Href        string  `json:"href,omitempty"`
		LogicalPops *string `json:"logicalpops,omitempty"`
	} `json:"resource_uri,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
	UUIDURL  string                 `json:"uuid_url,omitempty"`
}

type PopResponse struct {
	Meta struct {
		Limit      int     `json:"limit,omitempty"`
		Next       *string `json:"next,omitempty"`
		Offset     int     `json:"offset,omitempty"`
		Previous   *string `json:"previous,omitempty"`
		TotalCount int     `json:"total_count,omitempty"`
	} `json:"meta,omitempty"`
	Pops []Pop `json:"objects,omitempty"`
}

func GetPops(ec *EaaClient) ([]Pop, error) {
	apiURL := fmt.Sprintf("%s://%s/%s?shared=true", URL_SCHEME, ec.Host, POPS_URL)
	popsResponse := PopResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &popsResponse, true)
	if err != nil {
		return nil, err
	}
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(getResp)
		getPopsErrMsg := fmt.Errorf("%w: %s", ErrPopsGet, desc)
		return nil, getPopsErrMsg
	}

	var pops []Pop
	for _, pop := range popsResponse.Pops {
		if pop.Region == "" || pop.Name == "" || pop.UUIDURL == "" {
			continue
		}
		popData := Pop{
			Region:              pop.Region,
			Description:         pop.Description,
			Facility:            pop.Facility,
			Name:                pop.Name,
			PopCategory:         pop.PopCategory,
			PopType:             pop.PopType,
			RelatedFailoverPop:  pop.RelatedFailoverPop,
			RelatedFailoverName: pop.RelatedFailoverName,
			UUIDURL:             pop.UUIDURL,
		}
		pops = append(pops, popData)
	}

	return pops, nil
}

func GetPopUuid(ec *EaaClient, popregion string) (string, string, error) {

	pops, err := GetPops(ec)
	if err != nil {
		return "", "", ErrPopsGet
	}
	for _, pop := range pops {

		if pop.Region == popregion {
			return pop.Name, pop.UUIDURL, nil
		}

	}

	return "", "", ErrPopsGet
}
