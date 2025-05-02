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

	// Reading the comma-separated app names
	fmt.Println("Enter comma-separated app name search patterns: (example: *, app)")
	appNames, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading appNames:", err)
		return
	}
	appNames = strings.TrimSpace(appNames)

	edgercFile := ".edgerc"
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return
	}
	edgercPath := filepath.Join(currentDir, edgercFile)

	// Check if the file exists in the current directory
	if _, err := os.Stat(edgercPath); os.IsNotExist(err) {
		fmt.Printf("File '%s' not found in current directory '%s'.\n", edgercFile, currentDir)
		fmt.Print("Please enter the full path to the .edgerc file (API token): ")
		newPath, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading newPath:", err)
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
		if _, err := os.Stat(edgercPath); os.IsNotExist(err) {
			fmt.Printf("File '%s' does not exist.\n", edgercPath)
			return
		}
	}

	fmt.Printf("Using '%s' \n", edgercPath)
	edgerc, err := edgegrid.New(edgegrid.WithFile(edgercPath))
	if err != nil {
		fmt.Println("EdgeRc error")
	}

	eaaClient := &EaaClient{
		Client:           http.DefaultClient,
		ContractID:       contractID,
		Signer:           edgerc,
		AccountSwitchKey: accountSwitch,
		Host:             edgerc.Host,
	}
	err = GenerateConfiguration(eaaClient, edgercPath, appNames)
	if err != nil {
		fmt.Println(err)
	}
	println()
	println(generate_info)

}

func GenerateConfiguration(ec *EaaClient, edgercPath string, appNames string) error {
	fmt.Println("generating import blocks ...")
	fmt.Println()

	appsResponse := AppsResponse{}
	appList := strings.Split(strings.ToLower(appNames), ",")
	importBlocks := []importBlock{}

	for _, pattern := range appList {
		pattern = strings.TrimSpace(pattern)
		searchstring := matchesQueryString(pattern)
		fmt.Println(searchstring)
		apiURL := fmt.Sprintf("https://%s/%s?app_type__notin=5&%s", ec.Host, APPS_URL, searchstring)
		for apiURL != "" {
			getResp, err := ec.SendAPIRequest(apiURL, "GET", nil, &appsResponse, false)
			if err != nil {
				return err
			}

			if getResp.StatusCode < http.StatusOK || getResp.StatusCode >= http.StatusMultipleChoices {
				desc, _ := FormatErrorResponse(getResp)
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
			if err := file.Close(); err != nil {
				fmt.Printf("Error closing file: %v", err)
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
