package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v6/pkg/edgegrid"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	// Reading the contract ID
	fmt.Println("Enter Your Contract Id: ")
	contractID, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading contractID:", err)
		return
	}
	contractID = strings.TrimSpace(contractID)

	// Reading the account switch key
	fmt.Println("Enter Your accountSwitchKey (If accountSwitchKey is not required, please press ENTER) : ")
	accountSwitch, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading accountSwitch:", err)
		return
	}
	accountSwitch = strings.TrimSpace(accountSwitch)

	edgercFile := ".edgerc"
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return
	}
	edgercPath := filepath.Join(currentDir, edgercFile)

	// Check if the file exists in the current directory
	if _, statErr := os.Stat(edgercPath); os.IsNotExist(statErr) {
		fmt.Printf("File '%s' not found in current directory '%s'.\n", edgercFile, currentDir)
		fmt.Print("Please enter the full path to the .edgerc file (API token): ")
		newPath, readErr := reader.ReadString('\n')
		if readErr != nil {
			fmt.Println("Error reading newPath:", readErr)
			return
		}
		if newPath != "" {
			edgercPath = filepath.Join(strings.TrimSpace(newPath), edgercFile)
			fmt.Println("Edgerc Path:", edgercPath)
		} else {
			fmt.Println("No new path for .edgerc provided.")
			return
		}

		// Check if the new file path exists
		if _, statErr := os.Stat(edgercPath); os.IsNotExist(statErr) {
			fmt.Printf("File '%s' does not exist.\n", edgercPath)
			return
		}
	}

	fmt.Printf("Using '%s' \n", edgercPath)
	edgerc, err := edgegrid.New(edgegrid.WithFile(edgercPath))
	if err != nil {
		fmt.Printf("EdgeRc error: %s\n", err)
		return
	}

	eaaClient := &EaaClient{
		Client:           http.DefaultClient,
		ContractID:       contractID,
		Signer:           edgerc,
		AccountSwitchKey: accountSwitch,
		Host:             edgerc.Host,
	}

	reader2 := bufio.NewReader(os.Stdin)

	fmt.Print("Import applications? (Y/N): ")
	appChoice, err := reader2.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading application choice:", err)
		return
	}
	appChoice = strings.TrimSpace(strings.ToUpper(appChoice))
	if appChoice == "Y" {
		// Reading the comma-separated app names
		fmt.Println("Enter comma-separated app name search patterns: (example: *, app)")
		appNames, errName := reader.ReadString('\n')
		if errName != nil {
			fmt.Println("Error reading appNames:", errName)
			return
		}
		appNames = strings.TrimSpace(appNames)

		err = GenerateConfiguration(eaaClient, edgercPath, appNames)
		if err != nil {
			fmt.Println(err)
		} else {
			println()
			println(generateInfo)
		}
	}

	fmt.Print("Import All certificates? (Y/N): ")
	certChoice, err := reader2.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading certificate choice:", err)
		return
	}
	certChoice = strings.TrimSpace(strings.ToUpper(certChoice))
	if certChoice == "Y" {
		err = GenerateCertificateConfiguration(eaaClient, edgercPath)
		if err != nil {
			fmt.Println(err)
		} else {
			println()
			println(generateCertInfo)
		}
	}

	fmt.Print("Import All directories? (Y/N): ")
	dirChoice, err := reader2.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading directory choice:", err)
		return
	}
	dirChoice = strings.TrimSpace(strings.ToUpper(dirChoice))
	if dirChoice == "Y" {
		err = GenerateDirectoryConfiguration(eaaClient, edgercPath)
		if err != nil {
			fmt.Println(err)
		} else {
			println()
			println(generateDirInfo)
		}
	}

	fmt.Print("Import All IDPs? (Y/N): ")
	idpChoice, err := reader2.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading IDP choice:", err)
		return
	}
	idpChoice = strings.TrimSpace(strings.ToUpper(idpChoice))
	if idpChoice == "Y" {
		err = GenerateIDPConfiguration(eaaClient, edgercPath)
		if err != nil {
			fmt.Println(err)
		} else {
			println()
			println(generateIDPInfo)
		}
	}
}

func GenerateConfiguration(ec *EaaClient, edgercPath, appNames string) error {
	fmt.Println("generating import blocks ...")
	fmt.Println()

	appsResponse := AppsResponse{}
	appList := strings.Split(strings.ToLower(appNames), ",")
	importBlocks := []importBlock{}

	for _, pattern := range appList {
		pattern = strings.TrimSpace(pattern)
		searchstring := matchesQueryString(pattern)
		fmt.Println(searchstring)
		apiURL := fmt.Sprintf("https://%s/%s?app_type__notin=5&%s&fields=name,uuid_url", ec.Host, APPS_URL, searchstring)
		for apiURL != "" {
			getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &appsResponse, false)
			if err != nil {
				return err
			}

			if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
				desc := FormatErrorDescription(getResp)
				getAppErrMsg := fmt.Errorf("%w: %s", ErrGetApp, desc)
				return getAppErrMsg
			}

			for _, app := range appsResponse.Applications {
				if app.Name == "" || app.UUIDURL == "" {
					continue
				}
				replacedString := convertToValidTFName(app.Name)
				appName := fmt.Sprintf("eaa_application.%s\n", replacedString)
				importBlocks = append(importBlocks, importBlock{appID: app.UUIDURL, appName: appName})
			}

			if appsResponse.Metadata.Next != nil {
				fmt.Println(*appsResponse.Metadata.Next)
				nextURL := *appsResponse.Metadata.Next
				if strings.HasPrefix(nextURL, "/api/v3") {
					nextURL = nextURL[len("/api/v3"):]
					fmt.Println(nextURL)
				}
				apiURL = fmt.Sprintf("https://%s/%s%s", ec.Host, MGMT_POP_URL, nextURL)
				fmt.Println(apiURL)
			} else {
				apiURL = ""
			}
		}
	}

	if len(importBlocks) > 0 {
		file, err := os.Create("import_existing_apps.tf")
		if err != nil {
			fmt.Println("Error creating file:", err)
			return err
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				fmt.Printf("Error closing file: %v", closeErr)
			}
		}()
		err = writeProviderBlock(file, ec.ContractID, ec.AccountSwitchKey, edgercPath)
		if err != nil {
			fmt.Println("Error writing provider block to file:", err)
			return err
		}

		uniqueBlocks := make(map[string]importBlock)

		for _, block := range importBlocks {
			uniqueBlocks[block.appID] = block // This will overwrite duplicates
		}
		for _, block := range uniqueBlocks {
			fmt.Printf("generating import block for %s\n", block.appName)

			err := generateImportBlock(file, block.appID, block.appName)
			if err != nil {
				fmt.Printf("error generating import block %s\n", err)
			}
		}
		fmt.Printf("%d app imports added", len(uniqueBlocks))
	}

	return nil
}

func GenerateCertificateConfiguration(ec *EaaClient, edgercPath string) error {
	fmt.Println("generating certificate import blocks ...")
	fmt.Println()

	var importBlocks []importBlock

	certTypes := []struct {
		resourceType string
		certType     int
	}{
		{"eaa_custom_app_certificate", CERT_TYPE_APP},
		{"eaa_ca_certificate", CERT_TYPE_CA},
	}

	for _, ct := range certTypes {
		apiURL := fmt.Sprintf("https://%s/%s?cert_type=%d", ec.Host, CERTIFICATES_URL, ct.certType)
		for apiURL != "" {
			var certsResponse CertsResponse
			getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &certsResponse, false)
			if err != nil {
				return err
			}
			if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
				desc := FormatErrorDescription(getResp)
				return fmt.Errorf("certificate list failed: %s", desc)
			}

			for _, cert := range certsResponse.Objects {
				if cert.Name == "" || cert.UUIDURL == "" {
					continue
				}
				replacedString := convertToValidTFName(cert.Name)
				resourceName := fmt.Sprintf("%s.%s\n", ct.resourceType, replacedString)
				importBlocks = append(importBlocks, importBlock{appID: cert.UUIDURL, appName: resourceName})
			}

			if certsResponse.Metadata.Next != nil {
				nextURL := *certsResponse.Metadata.Next
				nextURL = strings.TrimPrefix(nextURL, "/api/v1")
				apiURL = fmt.Sprintf("https://%s/%s%s", ec.Host, "crux/v1/mgmt-pop", nextURL)
			} else {
				apiURL = ""
			}
		}
	}

	if len(importBlocks) > 0 {
		file, err := os.Create("import_existing_certs.tf")
		if err != nil {
			fmt.Println("Error creating file:", err)
			return err
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				fmt.Printf("Error closing file: %v", closeErr)
			}
		}()
		err = writeProviderBlock(file, ec.ContractID, ec.AccountSwitchKey, edgercPath)
		if err != nil {
			fmt.Println("Error writing provider block to file:", err)
			return err
		}

		uniqueBlocks := make(map[string]importBlock)
		for _, block := range importBlocks {
			uniqueBlocks[block.appID] = block
		}
		for _, block := range uniqueBlocks {
			fmt.Printf("generating import block for %s\n", block.appName)
			err := generateImportBlock(file, block.appID, block.appName)
			if err != nil {
				fmt.Printf("error generating import block %s\n", err)
			}
		}
		fmt.Printf("%d certificate imports added\n", len(uniqueBlocks))
	} else {
		fmt.Println("No certificates found to import.")
	}

	return nil
}

func GenerateIDPConfiguration(ec *EaaClient, edgercPath string) error {
	fmt.Println("generating IDP import blocks ...")
	fmt.Println()

	var importBlocks []importBlock

	apiURL := fmt.Sprintf("https://%s/%s", ec.Host, IDP_URL)
	for apiURL != "" {
		var idpsResponse IDPsResponse
		getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &idpsResponse, false)
		if err != nil {
			return err
		}
		if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
			desc := FormatErrorDescription(getResp)
			return fmt.Errorf("IDP list failed: %s", desc)
		}

		for _, idp := range idpsResponse.Objects {
			if idp.Name == "" || idp.UUIDURL == "" {
				continue
			}
			replacedString := convertToValidTFName(idp.Name)
			resourceName := fmt.Sprintf("eaa_idp.%s\n", replacedString)
			importBlocks = append(importBlocks, importBlock{appID: idp.UUIDURL, appName: resourceName})
		}

		if idpsResponse.Metadata.Next != nil {
			nextURL := *idpsResponse.Metadata.Next
			nextURL = strings.TrimPrefix(nextURL, "/api/v1")
			apiURL = fmt.Sprintf("https://%s/%s%s", ec.Host, "crux/v1/mgmt-pop", nextURL)
		} else {
			apiURL = ""
		}
	}

	if len(importBlocks) > 0 {
		file, err := os.Create("import_existing_idps.tf")
		if err != nil {
			fmt.Println("Error creating file:", err)
			return err
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				fmt.Printf("Error closing file: %v", closeErr)
			}
		}()
		err = writeProviderBlock(file, ec.ContractID, ec.AccountSwitchKey, edgercPath)
		if err != nil {
			fmt.Println("Error writing provider block to file:", err)
			return err
		}

		uniqueBlocks := make(map[string]importBlock)
		for _, block := range importBlocks {
			uniqueBlocks[block.appID] = block
		}
		for _, block := range uniqueBlocks {
			fmt.Printf("generating import block for %s\n", block.appName)
			err := generateImportBlock(file, block.appID, block.appName)
			if err != nil {
				fmt.Printf("error generating import block %s\n", err)
			}
		}
		fmt.Printf("%d IDP imports added\n", len(uniqueBlocks))
	} else {
		fmt.Println("No IDPs found to import.")
	}

	return nil
}

func GenerateDirectoryConfiguration(ec *EaaClient, edgercPath string) error {
	fmt.Println("generating directory import blocks ...")
	fmt.Println()

	var importBlocks []importBlock

	apiURL := fmt.Sprintf("https://%s/%s", ec.Host, DIRECTORIES_URL_V1)
	for apiURL != "" {
		var dirsResponse DirectoriesResponse
		getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &dirsResponse, false)
		if err != nil {
			return err
		}
		if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
			desc := FormatErrorDescription(getResp)
			return fmt.Errorf("directory list failed: %s", desc)
		}

		for _, dir := range dirsResponse.Objects {
			if dir.Name == "" || dir.UUIDURL == "" {
				continue
			}
			replacedString := convertToValidTFName(dir.Name)
			resourceName := fmt.Sprintf("eaa_directory.%s\n", replacedString)
			importBlocks = append(importBlocks, importBlock{appID: dir.UUIDURL, appName: resourceName})
		}

		if dirsResponse.Metadata.Next != nil {
			nextURL := *dirsResponse.Metadata.Next
			nextURL = strings.TrimPrefix(nextURL, "/api/v1")
			apiURL = fmt.Sprintf("https://%s/%s%s", ec.Host, "crux/v1/mgmt-pop", nextURL)
		} else {
			apiURL = ""
		}
	}

	if len(importBlocks) > 0 {
		file, err := os.Create("import_existing_directories.tf")
		if err != nil {
			fmt.Println("Error creating file:", err)
			return err
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				fmt.Printf("Error closing file: %v", closeErr)
			}
		}()
		err = writeProviderBlock(file, ec.ContractID, ec.AccountSwitchKey, edgercPath)
		if err != nil {
			fmt.Println("Error writing provider block to file:", err)
			return err
		}

		uniqueBlocks := make(map[string]importBlock)
		for _, block := range importBlocks {
			uniqueBlocks[block.appID] = block
		}
		for _, block := range uniqueBlocks {
			fmt.Printf("generating import block for %s\n", block.appName)
			err := generateImportBlock(file, block.appID, block.appName)
			if err != nil {
				fmt.Printf("error generating import block %s\n", err)
			}
		}
		fmt.Printf("%d directory imports added\n", len(uniqueBlocks))
	} else {
		fmt.Println("No directories found to import.")
	}

	return nil
}
