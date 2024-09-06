package client

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrAgentsGet = errors.New("connectors get failed")
)

type Connector struct {
	Name                  string  `json:"name,omitempty"`
	UUIDURL               string  `json:"uuid_url,omitempty"`
	ActivationCode        *string `json:"activation_code,omitempty"`
	AgentInfraType        int     `json:"agent_infra_type,omitempty"`
	AgentType             int     `json:"agent_type,omitempty"`
	AgentVersion          *string `json:"agent_version,omitempty"`
	CPU                   *string `json:"cpu,omitempty"`
	DataService           bool    `json:"data_service,omitempty"`
	DebugChannelPermitted bool    `json:"debug_channel_permitted,omitempty"`
	Description           *string `json:"description,omitempty"`
	DHCP                  string  `json:"dhcp,omitempty"`
	DiskSize              *string `json:"disk_size,omitempty"`
	DownAppsCount         int     `json:"down_apps_count,omitempty"`
	DownDirCount          int     `json:"down_dir_count,omitempty"`
	DownloadURL           *string `json:"download_url,omitempty"`
	Gateway               *string `json:"gateway,omitempty"`
	GeoLocation           *string `json:"geo_location,omitempty"`
	Hostname              *string `json:"hostname,omitempty"`
	IPAddr                *string `json:"ip_addr,omitempty"`
	LastCheckin           *string `json:"last_checkin,omitempty"`
	LoadStatus            *string `json:"load_status,omitempty"`
	MAC                   *string `json:"mac,omitempty"`
	ManualOverride        bool    `json:"manual_override,omitempty"`
	OSUpgradesUpToDate    bool    `json:"os_upgrades_up_to_date,omitempty"`
	OSVersion             *string `json:"os_version,omitempty"`
	Package               int     `json:"package,omitempty"`
	Policy                string  `json:"policy,omitempty"`
	PrivateIP             *string `json:"private_ip,omitempty"`
	PublicIP              *string `json:"public_ip,omitempty"`
	RAMSize               *string `json:"ram_size,omitempty"`
	Reach                 int     `json:"reach,omitempty"`
	Region                *string `json:"region,omitempty"`
	State                 int     `json:"state,omitempty"`
	Status                int     `json:"status,omitempty"`
	Subnet                *string `json:"subnet,omitempty"`
	Timezone              *string `json:"tz,omitempty"`
	UnificationStatus     int     `json:"unification_status,omitempty"`
	UpAppsCount           int     `json:"up_apps_count,omitempty"`
	UpDirCount            int     `json:"up_dir_count,omitempty"`
	UUID                  string  `json:"uuid,omitempty"`
}

type ConnectorResponse struct {
	Meta struct {
		Limit      int     `json:"limit,omitempty"`
		Next       *string `json:"next,omitempty"`
		Offset     int     `json:"offset,omitempty"`
		Previous   *string `json:"previous,omitempty"`
		TotalCount int     `json:"total_count,omitempty"`
	} `json:"meta,omitempty"`
	Connectors []Connector `json:"objects,omitempty"`
}

func GetAgents(ec *EaaClient) ([]Connector, error) {
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, AGENTS_URL)
	agentsResponse := ConnectorResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &agentsResponse, false)
	if err != nil {
		return nil, err
	}
	if !(getResp.StatusCode >= http.StatusOK && getResp.StatusCode < http.StatusMultipleChoices) {
		desc, _ := FormatErrorResponse(getResp)
		updErrMsg := fmt.Errorf("%w: %s", ErrAgentsGet, desc)

		return nil, updErrMsg
	}

	var agents []Connector
	for _, conn := range agentsResponse.Connectors {
		if conn.Name == "" || conn.UUIDURL == "" {
			continue
		}
		agents = append(agents, conn)
	}

	return agents, nil
}

func GetAgentUUIDs(ec *EaaClient, agentNames []string) ([]string, error) {
	agents, err := GetAgents(ec)
	if err != nil {
		return nil, ErrAgentsGet
	}

	agentUUIDs := make([]string, 0)
	for _, agentName := range agentNames {
		for _, agentData := range agents {
			if agentName == agentData.Name {
				agentUUIDs = append(agentUUIDs, agentData.UUIDURL)
				break
			}
		}
	}

	return agentUUIDs, nil
}
