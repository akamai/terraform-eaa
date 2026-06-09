package client

import (
	"context"
	"fmt"
	"net/http"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type Pop struct {
	Description *string                `json:"description,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
	ResourceURI struct {
		LogicalPops *string `json:"logicalpops,omitempty"`
		Href        string  `json:"href,omitempty"`
	} `json:"resource_uri,omitempty"`
	CreatedAt           string   `json:"created_at,omitempty"`
	Facility            string   `json:"facility,omitempty"`
	ModifiedAt          string   `json:"modified_at,omitempty"`
	Name                string   `json:"name,omitempty"`
	PopType             string   `json:"pop_type,omitempty"`
	Region              string   `json:"region,omitempty"`
	RelatedFailoverPop  string   `json:"related_failover_pop,omitempty"`
	RelatedFailoverName string   `json:"related_failover_pop_name,omitempty"`
	UUIDURL             string   `json:"uuid_url,omitempty"`
	PopCategory         []string `json:"pop_category,omitempty"`
}

type PopResponse struct {
	Pops []Pop `json:"objects,omitempty"`
	Meta struct {
		Next       *string `json:"next,omitempty"`
		Previous   *string `json:"previous,omitempty"`
		Limit      int     `json:"limit,omitempty"`
		Offset     int     `json:"offset,omitempty"`
		TotalCount int     `json:"total_count,omitempty"`
	} `json:"meta,omitempty"`
}

func GetPops(ctx context.Context, ec *EaaClient) ([]Pop, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagPopTraffic, logging.TagList}
	apiURL := fmt.Sprintf("%s://%s/%s?shared=true", URL_SCHEME, ec.Host, POPS_URL)
	popsResponse := PopResponse{}

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &popsResponse, true)
	if err != nil {
		return nil, logging.Wrapf(err, tags, "get pops API request failed")
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "pops get failed: %s", desc)
	}

	var pops []Pop
	for i := range popsResponse.Pops {
		pop := &popsResponse.Pops[i]
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

func GetPopUUID(ctx context.Context, ec *EaaClient, popregion string) (name, uuidURL string, err error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagPopTraffic, logging.TagRead}

	pops, err := GetPops(ctx, ec)
	if err != nil {
		return "", "", logging.Wrapf(err, tags, "failed to get pops")
	}
	for i := range pops {
		pop := &pops[i]

		if pop.Region == popregion {
			return pop.Name, pop.UUIDURL, nil
		}

	}

	return "", "", logging.Errorf(tags, "pop not found for region: %s", popregion)
}
