package idanalyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type AMLAPI struct {
	apiKey        string
	apiEndpoint   string
	amlDatabases  string
	amlEntityType string
}

type AMLResponse struct {
	Items []AMLResponseItem `json:"items"`
}

type AMLResponseItem struct {
	Entity         string                          `json:"entity,omitempty"`
	FullName       []string                        `json:"fullname,omitempty"`
	FirstName      []string                        `json:"firstname,omitempty"`
	MiddleName     []string                        `json:"middlename,omitempty"`
	LastName       []string                        `json:"lastname,omitempty"`
	Alias          []string                        `json:"alias,omitempty"`
	DOB            []string                        `json:"dob,omitempty"`
	Address        []string                        `json:"address,omitempty"`
	Nationality    []string                        `json:"nationality,omitempty"`
	BirthPlace     []string                        `json:"birthplace,omitempty"`
	Gender         []string                        `json:"gender,omitempty"`
	DocumentNumber []AMLResponseItemDocumentNumber `json:"documentnumber,omitempty"`
	Program        []string                        `json:"program,omitempty"`
	Note           []string                        `json:"note,omitempty"`
	Status         []string                        `json:"status,omitempty"`
	Time           string                          `json:"time,omitempty"`
	Source         []string                        `json:"source,omitempty"`
	Database       string                          `json:"database,omitempty"`
}

type AMLResponseItemDocumentNumber struct {
	ID          string `json:"id,omitempty"`
	IDFormatted string `json:"id_formatted,omitempty"`
	Country     string `json:"country,omitempty"`
	Type        string `json:"type,omitempty"`
	Summary     string `json:"summary,omitempty"`
}

// Initialize AML API with an API key and region (US (default), EU)
func NewAMLAPI(apiKey, region string) (AMLAPI, error) {
	if apiKey == "" {
		return AMLAPI{}, errors.New("please provide an API key")
	}

	return AMLAPI{
		apiKey:      apiKey,
		apiEndpoint: endpointFromRegion(region, "aml"),
	}, nil
}

// SETTERS

// Specify the source databases to perform AML search
// If left blank, all source databases will be checked
// Separate each database code with comma, for example: un_sc,us_ofac
//
// For full list of source databases and corresponding code visit AML API Overview
func (a *AMLAPI) SetAMLDatabase(databases string) {
	// if databases == "" {
	// 	databases = "au_dfat,ca_dfatd,ch_seco,eu_fsf,fr_tresor_gels_avoir,gb_hmt,ua_sfms,un_sc,us_ofac,eu_cor,eu_meps,global_politicians,interpol_red"
	// }

	a.amlDatabases = databases
}

// Return only entities with specified entity type
// Leave blank to return both person and legal entity.
func (a *AMLAPI) SetEntityType(entityType string) error {
	if entityType != "person" && entityType != "legalentity" && entityType != "" {
		return errors.New(`entity type should be either empty, "person" or "legalentity"`)
	}
	a.amlEntityType = entityType

	return nil
}

// ACTIONS

// Search AML Database using a person or company's name or alias
func (a *AMLAPI) SearchByName(name, country, dob string) (AMLResponse, error) {
	return a.callAPI(amlRequest{
		Name:    name,
		Country: country,
		DOB:     dob,
	})
}

// Search AML Database using a document number (Passport, ID Card or any identification documents)
func (a *AMLAPI) SearchByIDNumber(documentNumber, country, dob string) (AMLResponse, error) {
	return a.callAPI(amlRequest{
		DocumentNumber: documentNumber,
		Country:        country,
		DOB:            dob,
	})
}

// PRIVATE

type amlRequest struct {
	ApiKey         string `json:"apikey"`
	Database       string `json:"database"`
	Entity         string `json:"entity"`
	Client         string `json:"client"`
	Name           string `json:"name"`
	DocumentNumber string `json:"documentnumber"`
	Country        string `json:"country"`
	DOB            string `json:"dob"`
}

func (a *AMLAPI) callAPI(request amlRequest) (AMLResponse, error) {
	request.ApiKey = a.apiKey
	request.Database = a.amlDatabases
	request.Entity = a.amlEntityType
	request.Client = "go-sdk"

	body, _ := json.Marshal(request)

	if response, err := http.Post(a.apiEndpoint, "application/json", bytes.NewBuffer(body)); err != nil {
		return AMLResponse{}, fmt.Errorf("failed to connect to API server: %s", err.Error())
	} else {
		var result AMLResponse

		body, _ := io.ReadAll(response.Body)
		json.Unmarshal(body, &result)

		return result, nil
	}
}
