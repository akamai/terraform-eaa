package eaaprovider

import (
	"git.source.akamai.com/terraform-provider-eaa/pkg/client"
	"github.com/hashicorp/go-hclog"
)

// validateRDPConfiguration validates RDP configuration settings
func validateRDPConfiguration(settings map[string]interface{}, appType, appProfile string, logger hclog.Logger) error {
	logger.Debug("validateRDPConfiguration called with appType='%s', appProfile='%s'", appType, appProfile)
	logger.Debug("validateRDPConfiguration - settings keys: %v", getMapKeys(settings))

	// Check if any RDP configuration settings are present
	hasRDPConfigurationSettings := false
	rdpConfigurationFields := []string{
		"rdp_initial_program", "remote_app", "remote_app_args", "remote_app_dir",
		"rdp_tls1", "remote_spark_mapClipboard", "rdp_legacy_mode", "remote_spark_audio",
		"remote_spark_mapPrinter", "remote_spark_printer", "remote_spark_mapDisk",
		"remote_spark_disk", "remote_spark_recording",
	}

	for _, field := range rdpConfigurationFields {
		if _, exists := settings[field]; exists {
			hasRDPConfigurationSettings = true
			break
		}
	}

	if !hasRDPConfigurationSettings {
		logger.Debug("No RDP configuration settings found, skipping validation")
		return nil // No RDP configuration settings, skip validation
	}

	logger.Debug("RDP configuration settings found, validating with app_type: %s, app_profile: %s", appType, appProfile)

	// STEP 1: Validate app type and profile restrictions
	if appType != "" {
		if appType != "enterprise" {
			return client.ErrRDPConfigurationNotSupportedForAppType
		}

		if appProfile != "" {
			if appProfile != "rdp" {
				return client.ErrRDPConfigurationNotSupportedForProfile
			}
			logger.Debug("RDP configuration allowed for enterprise app with RDP profile")
		} else {
			logger.Debug("RDP configuration allowed for enterprise app (profile not specified)")
		}
	} else {
		// When appType is empty (schema validation), we cannot validate app type restrictions
		// but we can still validate the RDP configuration structure
		logger.Debug("App type not provided, skipping app type validation but continuing with RDP configuration structure validation")
		// During schema validation, we'll be more lenient and only validate the structure
		// The app type validation will happen during runtime validation (terraform apply)
	}

	// STEP 2: Validate individual RDP configuration parameters

	// Validate RDP Initial Program (Always available for RDP)
	if rdpInitialProgram, exists := settings["rdp_initial_program"]; exists {
		if _, ok := rdpInitialProgram.(string); !ok {
			return client.ErrRDPInitialProgramNotString
		}
		logger.Debug("rdp_initial_program validated - always available for RDP")
	}

	// Validate Remote App settings (Always available for RDP)
	remoteAppFields := []string{"remote_app", "remote_app_args", "remote_app_dir"}
	for _, field := range remoteAppFields {
		if val, exists := settings[field]; exists {
			if _, ok := val.(string); !ok {
				return client.ErrRDPParameterNotString
			}
		}
	}

	// Validate RDP TLS v1 (Always available for RDP)
	if rdpTls1, exists := settings["rdp_tls1"]; exists {
		if _, ok := rdpTls1.(bool); !ok {
			return client.ErrRDPTLS1NotBoolean
		}
		logger.Debug("rdp_tls1 validated - always available for RDP")
	}

	// Validate Remote Spark features (RDP V2 only)
	// Note: In a real implementation, we would need to know the RDP version (V1 vs V2)
	// For now, we'll validate the structure but note that these are V2-only features
	remoteSparkV2Fields := []string{
		"remote_spark_mapClipboard", "rdp_legacy_mode", "remote_spark_audio",
		"remote_spark_mapPrinter", "remote_spark_printer", "remote_spark_mapDisk", "remote_spark_disk",
	}

	for _, field := range remoteSparkV2Fields {
		if val, exists := settings[field]; exists {
			if _, ok := val.(string); !ok {
				if _, ok := val.(bool); !ok {
					return client.ErrRDPParameterNotStringOrBoolean
				}
			}
			logger.Debug("%s validated - RDP V2 feature", field)
		}
	}

	// Validate Session Recording (RDP V1 only)
	if remoteSparkRecording, exists := settings["remote_spark_recording"]; exists {
		if _, ok := remoteSparkRecording.(bool); !ok {
			return client.ErrRemoteSparkRecordingNotBoolean
		}
		logger.Debug("remote_spark_recording validated - RDP V1 feature")
	}

	// STEP 3: Validate conditional dependencies
	// Remote Printer Name requires Remote Printing to be enabled
	if _, exists := settings["remote_spark_printer"]; exists {
		if _, mapPrinterExists := settings["remote_spark_mapPrinter"]; !mapPrinterExists {
			logger.Warn("remote_spark_printer is set but remote_spark_mapPrinter is not enabled")
			return client.ErrRDPPrinterRequiresMapPrinter
		}
	}

	// File Transfer Name requires File Transfer to be enabled
	if _, exists := settings["remote_spark_disk"]; exists {
		if _, mapDiskExists := settings["remote_spark_mapDisk"]; !mapDiskExists {
			logger.Warn("remote_spark_disk is set but remote_spark_mapDisk is not enabled")
			return client.ErrRDPDiskRequiresMapDisk
		}
	}

	return nil
}
