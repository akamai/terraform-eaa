package client

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"git.source.akamai.com/terraform-provider-eaa/pkg/logging"
)

type AppAgentResponse struct {
	Agents []struct {
		Agent struct {
			Name    string `json:"name,omitempty"`
			UUIDURL string `json:"uuid_url,omitempty"`
		} `json:"agent,omitempty"`
		ResourceURI struct {
			Href string `json:"href,omitempty"`
		} `json:"resource_uri,omitempty"`
	} `json:"objects,omitempty"`
}

type AssignAgents struct {
	AppID      string   `json:"app_id"`
	AgentNames []string `json:"agents"`
}

type Agent struct {
	UUIDURL string `json:"uuid_url"`
}

type AssignAgentsRequest struct {
	Agents []Agent `json:"agents"`
}

func (aar *AssignAgents) AssignAgents(ctx context.Context, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagAgent, logging.TagAssign}
	logging.Info(ctx, "AssignAgents", tags)

	var agents AssignAgentsRequest
	agentUUIDs, err := GetAgentUUIDs(ctx, ec, aar.AgentNames)
	if err != nil {
		logging.Warn(ctx, "unable to lookup uuids from agent names", tags)
		return err
	}
	for _, uuid := range agentUUIDs {
		agent := Agent{
			UUIDURL: uuid,
		}
		agents.Agents = append(agents.Agents, agent)
		logging.Debug(ctx, "agent uuid", tags, map[string]any{"uuid": uuid})
	}

	if len(agents.Agents) == 0 {
		logging.Warn(ctx, "no connectors to assign", tags)
		return nil
	}

	apiURL := fmt.Sprintf("%s://%s/%s/%s/agents", URL_SCHEME, ec.Host, APPS_URL, aar.AppID)
	logging.Debug(ctx, "api URL", tags, map[string]any{"url": apiURL})
	agentsResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", agents, nil, false)
	if err != nil {
		logging.Warn(ctx, "assign agents failed", tags, map[string]any{"status": agentsResp.StatusCode})
		return err
	}
	if agentsResp.StatusCode < http.StatusOK || agentsResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(agentsResp)
		logging.Warn(ctx, "assign agents failed", tags, map[string]any{"status": agentsResp.StatusCode, "description": desc})
		return logging.Errorf(tags, "connectors assign failed: %s", desc)
	}
	return nil
}

func (app *Application) GetAppAgents(ctx context.Context, ec *EaaClient) ([]string, error) {
	tags := []logging.Tag{logging.TagAPI, logging.TagAgent, logging.TagRead}
	logging.Info(ctx, "GetAppAgents", tags)

	apiURL := fmt.Sprintf("%s://%s/%s/%s/agents", URL_SCHEME, ec.Host, APPS_URL, app.UUIDURL)
	agentsResponse := AppAgentResponse{}

	getResp, err := ec.SendAPIRequest(ctx, apiURL, "GET", nil, &agentsResponse, false)
	if err != nil {
		return nil, err
	}
	if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(getResp)
		return nil, logging.Errorf(tags, "connectors get failed: %s", desc)
	}

	agentNames := make([]string, 0, len(agentsResponse.Agents))
	for _, agent := range agentsResponse.Agents {
		agentNames = append(agentNames, agent.Agent.Name)
	}
	sort.Strings(agentNames)

	return agentNames, nil
}

type UnAssignAgentsRequest struct {
	Agents []string `json:"agents"`
}

func (aar *AssignAgents) UnAssignAgents(ctx context.Context, ec *EaaClient) error {
	tags := []logging.Tag{logging.TagAPI, logging.TagAgent, logging.TagAssign}
	logging.Info(ctx, "UnAssignAgents", tags)

	var agents UnAssignAgentsRequest
	agentUUIDs, err := GetAgentUUIDs(ctx, ec, aar.AgentNames)
	if err != nil {
		logging.Warn(ctx, "unable to lookup uuids from agent names", tags)
		return err
	}
	for _, uuid := range agentUUIDs {
		agents.Agents = append(agents.Agents, uuid)
		logging.Debug(ctx, "agent uuid", tags, map[string]any{"uuid": uuid})
	}
	if len(agents.Agents) == 0 {
		logging.Warn(ctx, "no connectors to unassign", tags)
		return nil
	}

	apiURL := fmt.Sprintf("%s://%s/%s/%s/agents?method=delete", URL_SCHEME, ec.Host, APPS_URL, aar.AppID)
	logging.Debug(ctx, "api URL", tags, map[string]any{"url": apiURL})
	agentsResp, err := ec.SendAPIRequest(ctx, apiURL, "POST", agents, nil, false)
	if err != nil {
		logging.Warn(ctx, "unassign agents failed", tags, map[string]any{"status": agentsResp.StatusCode})
		return err
	}
	if agentsResp.StatusCode < http.StatusOK || agentsResp.StatusCode >= http.StatusMultipleChoices {
		desc := FormatErrorDescription(agentsResp)
		logging.Warn(ctx, "unassign agents failed", tags, map[string]any{"status": agentsResp.StatusCode, "description": desc})
		return logging.Errorf(tags, "connectors unassign failed: %s", desc)
	}
	return nil
}
