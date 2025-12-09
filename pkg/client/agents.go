package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	ErrAgentsGet  = errors.New("agents get failed")
	ErrConnCreate = errors.New("connector create failed")
	ErrConnUpdate = errors.New("connector update failed")
	ErrConnDelete = errors.New("connector delete failed")
)

type ConnAdvancedSettings struct {
	Network_Info []string `json:"network_info,omitempty"`
}

type CreateConnectorRequest struct {
	Description           *string              `json:"description"`
	Name                  string               `json:"name"`
	AdvancedSettings      ConnAdvancedSettings `json:"advanced_settings"`
	Status                int                  `json:"status"`
	Package               int                  `json:"package"`
	AuthService           bool                 `json:"auth_service"`
	DataService           bool                 `json:"data_service"`
	DebugChannelPermitted bool                 `json:"debug_channel_permitted"`
}

func (ccr *CreateConnectorRequest) CreateConnectorRequestFromSchema(ctx context.Context, d *schema.ResourceData, ec *EaaClient) error {
	logger := ec.Logger

	// validate and set the name field
	name, ok := d.GetOk("name")
	if !ok {
		logger.Error("create Connector failed. 'name' is required but missing")
		return ErrInvalidValue
	}
	nameStr, ok := name.(string)
	if !ok || nameStr == "" {
		logger.Error("create Connector failed. 'name' must be a non-empty string")
		return ErrInvalidType
	}
	ccr.Name = nameStr

	// set the description field if present
	if description, ok := d.GetOk("description"); ok {
		descriptionStr, ok := description.(string)
		if ok && descriptionStr != "" {
			ccr.Description = &descriptionStr
		}
	}

	// set the debug_channel_permitted field with default value if not present
	if debugPermitted, ok := d.GetOk("debug_channel_permitted"); ok {
		debugChPermitted, ok := debugPermitted.(bool)
		if ok {
			ccr.DebugChannelPermitted = debugChPermitted
		} else {
			logger.Error("create Connector failed. 'debug_channel_permitted' must be a boolean")
			return ErrInvalidType
		}
	} else {
		logger.Info("debug_channel_permitted is not present, defaulting to false")
		ccr.DebugChannelPermitted = false
	}

	// validate and set the package field
	connPackage, ok := d.GetOk("package")
	if !ok {
		logger.Error("create Connector failed. 'package' is required but missing")
		return ErrInvalidValue
	}
	connPackageStr, ok := connPackage.(string)
	if !ok {
		logger.Error("create Connector failed. 'package' must be a string")
		return ErrInvalidType
	}
	atype := ConnPackageType(connPackageStr)
	value, err := atype.ToInt()
	if err != nil {
		logger.Error("create Connector failed. 'package' is invalid")
		return ErrInvalidValue
	}
	ccr.Package = value

	// handle advanced_settings if present
	if advSettingsData, ok := d.GetOk("advanced_settings"); ok {
		advSettingsList, ok := advSettingsData.([]interface{})
		if ok && len(advSettingsList) > 0 {
			if advSettingsData, ok := advSettingsList[0].(map[string]interface{}); ok {
				advSettings := ConnAdvancedSettings{}
				if networkInfoData, ok := advSettingsData["network_info"]; ok {
					networkInfoList, ok := networkInfoData.([]interface{})
					if ok {
						for _, networkInfo := range networkInfoList {
							if ip, ok := networkInfo.(string); ok {
								advSettings.Network_Info = append(advSettings.Network_Info, ip)
							}
						}
					}
				}

				// assign default value if 'Network_Info' is empty
				if len(advSettings.Network_Info) == 0 {
					advSettings.Network_Info = []string{"0.0.0.0/0"}
				}

				ccr.AdvancedSettings = advSettings
			}
		}
	}

	// set default 'AdvancedSettings' if not populated
	if ccr.AdvancedSettings.Network_Info == nil {
		ccr.AdvancedSettings = ConnAdvancedSettings{
			Network_Info: []string{"0.0.0.0/0"},
		}
	}

	// Set additional fields
	ccr.Status = STATE_ENABLED
	ccr.AuthService = true
	ccr.DataService = true

	return nil
}

func (cur *Connector) UpdateConnector(ctx context.Context, d *schema.ResourceData, ec *EaaClient) (*Connector, error) {
	createRequest := CreateConnectorRequest{}
	err := createRequest.CreateConnectorRequestFromSchema(ctx, d, ec)
	if err != nil {
		ec.Logger.Error("create connector failed. err ", err)
		return nil, err
	}
	cur.Name = createRequest.Name
	cur.Description = createRequest.Description
	cur.AdvancedSettings = createRequest.AdvancedSettings
	cur.DebugChannelPermitted = createRequest.DebugChannelPermitted
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, AGENTS_URL, cur.UUIDURL)

	var connResp Connector
	updateConnResp, err := ec.SendAPIRequest(apiURL, "PUT", cur, &connResp, false)
	if err != nil {
		ec.Logger.Error("update Connector failed.", "error", err)
		return nil, err
	}

	if updateConnResp.StatusCode != http.StatusOK {
		desc, _ := FormatErrorResponse(updateConnResp)
		updateErrMsg := fmt.Errorf("%w: %s", ErrConnUpdate, desc)

		ec.Logger.Error("update Connector failed. StatusCode %d %s", updateConnResp.StatusCode, desc)
		return nil, updateErrMsg
	}

	ec.Logger.Info("update Connector succeeded.", "name", cur.Name)
	return &connResp, nil
}

type Connector struct {
	IPAddr                *string              `json:"ip_addr,omitempty"`
	OSVersion             *string              `json:"os_version,omitempty"`
	PublicIP              *string              `json:"public_ip,omitempty"`
	DiskSize              *string              `json:"disk_size,omitempty"`
	RAMSize               *string              `json:"ram_size,omitempty"`
	Timezone              *string              `json:"tz,omitempty"`
	Subnet                *string              `json:"subnet,omitempty"`
	AgentVersion          *string              `json:"agent_version,omitempty"`
	CPU                   *string              `json:"cpu,omitempty"`
	ConnectorPool         *ConnectorPool       `json:"connector_pool,omitempty"`
	Region                *string              `json:"region,omitempty"`
	DownloadURL           *string              `json:"download_url,omitempty"`
	ActivationCode        *string              `json:"activation_code,omitempty"`
	MAC                   *string              `json:"mac,omitempty"`
	Description           *string              `json:"description,omitempty"`
	Gateway               *string              `json:"gateway,omitempty"`
	GeoLocation           *string              `json:"geo_location,omitempty"`
	Hostname              *string              `json:"hostname,omitempty"`
	PrivateIP             *string              `json:"private_ip,omitempty"`
	LastCheckin           *string              `json:"last_checkin,omitempty"`
	LoadStatus            *string              `json:"load_status,omitempty"`
	DHCP                  string               `json:"dhcp,omitempty"`
	Name                  string               `json:"name,omitempty"`
	UUID                  string               `json:"uuid,omitempty"`
	UUIDURL               string               `json:"uuid_url,omitempty"`
	Policy                string               `json:"policy,omitempty"`
	AdvancedSettings      ConnAdvancedSettings `json:"advanced_settings"`
	Reach                 int                  `json:"reach,omitempty"`
	UnificationStatus     int                  `json:"unification_status,omitempty"`
	AgentInfraType        int                  `json:"agent_infra_type,omitempty"`
	AgentType             int                  `json:"agent_type,omitempty"`
	Package               int                  `json:"package,omitempty"`
	State                 int                  `json:"state,omitempty"`
	Status                int                  `json:"status,omitempty"`
	UpDirCount            int                  `json:"up_dir_count,omitempty"`
	UpAppsCount           int                  `json:"up_apps_count,omitempty"`
	DebugChannelPermitted bool                 `json:"debug_channel_permitted,omitempty"`
	AgentUpgradeEnabled   bool                 `json:"agent_upgrade_enabled,omitempty"`
	AgentUpgradeSuspended bool                 `json:"agent_upgrade_suspended,omitempty"`
	DataService           bool                 `json:"data_service,omitempty"`
	ManualOverride        bool                 `json:"manual_override,omitempty"`
	OSUpgradesUpToDate    bool                 `json:"os_upgrades_up_to_date,omitempty"`
}

func (ccr *CreateConnectorRequest) CreateConnector(ctx context.Context, ec *EaaClient) (*Connector, error) {
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, AGENTS_URL)

	var connResp Connector
	createConnResp, err := ec.SendAPIRequest(apiURL, "POST", ccr, &connResp, false)
	if err != nil {
		ec.Logger.Error("create connector failed.", "error", err)
		return nil, err
	}

	if createConnResp.StatusCode != http.StatusOK {
		desc, _ := FormatErrorResponse(createConnResp)
		createErrMsg := fmt.Errorf("%w: %s", ErrConnCreate, desc)

		ec.Logger.Error("create Connector failed. StatusCode %d %s", createConnResp.StatusCode, desc)
		return nil, createErrMsg
	}

	ec.Logger.Info("create Connector succeeded.", "name", ccr.Name)
	return &connResp, nil
}

type ConnectorResponse struct {
	Connectors []Connector `json:"objects,omitempty"`
	Meta       struct {
		Next       *string `json:"next,omitempty"`
		Previous   *string `json:"previous,omitempty"`
		Limit      int     `json:"limit,omitempty"`
		Offset     int     `json:"offset,omitempty"`
		TotalCount int     `json:"total_count,omitempty"`
	} `json:"meta,omitempty"`
}

func GetAgents(ec *EaaClient) ([]Connector, error) {
	apiURL := fmt.Sprintf("%s://%s/%s", URL_SCHEME, ec.Host, AGENTS_URL)
	agentsResponse := ConnectorResponse{}

	getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &agentsResponse, false)
	if err != nil {
		return nil, err
	}

	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
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

func DeleteConnector(ec *EaaClient, conn_uuid_url string) error {
	apiURL := fmt.Sprintf("%s://%s/%s/%s", URL_SCHEME, ec.Host, AGENTS_URL, conn_uuid_url)

	deleteResp, err := ec.SendAPIRequest(apiURL, http.MethodDelete, nil, nil, false)
	if err != nil {
		return err
	}

	if deleteResp.StatusCode < http.StatusOK || deleteResp.StatusCode >= http.StatusMultipleChoices {
		return ErrConnDelete
	}
	return nil
}
