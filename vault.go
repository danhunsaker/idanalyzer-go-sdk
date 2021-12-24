package idanalyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type VaultAPI struct {
	apiKey      string
	apiEndpoint string
}

type VaultItemRequest struct {
	ID string `json:"id"`
}

type VaultListRequest struct {
	OrderBy string   `json:"orderby"`
	Sort    string   `json:"sort"`
	Limit   uint     `json:"limit"`
	Offset  uint     `json:"offset"`
	Filter  []string `json:"filter"`
}

type VaultItemResponse struct {
	Error   *APIError  `json:"error"`
	Success bool       `json:"success"`
	Data    *VaultData `json:"data"`
}

type VaultListResponse struct {
	Error      *APIError   `json:"error"`
	Limit      uint        `json:"limit"`
	Offset     uint        `json:"offset"`
	NextOffset uint        `json:"nextoffset"`
	Total      uint        `json:"total"`
	Items      []VaultData `json:"items"`
}

type VaultSuccessResponse struct {
	Success uint      `json:"success"`
	Error   *APIError `json:"error"`
}

type VaultImageResponse struct {
	Success uint            `json:"success"`
	Error   *APIError       `json:"error"`
	Image   *VaultImageData `json:"image"`
}

type VaultFaceSearchResponse struct {
	Error *APIError   `json:"error"`
	Items []VaultData `json:"items"`
}

type VaultData struct {
	ID                      string           `json:"id"`
	CreateTime              string           `json:"createtime"`
	UpdateTime              string           `json:"updatetime"`
	TrustLevel              string           `json:"trustlevel"`
	TrustNote               string           `json:"trustnote"`
	DocuPassReference       string           `json:"docupass_reference"`
	DocuPassSuccess         int              `json:"docupass_success"`
	DocuPassFailedReason    string           `json:"docupass_failedreason"`
	DocuPassCustomID        string           `json:"docupass_customid"`
	DocumentNumber          string           `json:"documentNumber"`
	DocumentNumberFormatted string           `json:"documentNumber_formatted"`
	PersonalNumber          string           `json:"personalNumber"`
	FirstName               string           `json:"firstName"`
	MiddleName              string           `json:"middleName"`
	LastName                string           `json:"lastName"`
	FullName                string           `json:"fullName"`
	FirstNameLocal          string           `json:"firstName_local"`
	MiddleNameLocal         string           `json:"middleName_local"`
	LastNameLocal           string           `json:"lastName_local"`
	FullNameLocal           string           `json:"fullName_local"`
	DOB                     string           `json:"dob"`
	Issued                  string           `json:"issued"`
	Expiry                  string           `json:"expiry"`
	Sex                     string           `json:"sex"`
	Height                  string           `json:"height"`
	Weight                  string           `json:"weight"`
	Address1                string           `json:"address1"`
	Address2                string           `json:"address2"`
	Postcode                string           `json:"postcode"`
	PlaceOfBirth            string           `json:"placeOfBirth"`
	DocumentType            string           `json:"documentType"`
	DocumentName            string           `json:"documentName"`
	VehicleClass            string           `json:"vehicleClass"`
	Restrictions            string           `json:"restrictions"`
	Endorsement             string           `json:"endorsement"`
	HairColor               string           `json:"hairColor"`
	EyeColor                string           `json:"eyeColor"`
	Email                   string           `json:"email"`
	Mobile                  string           `json:"mobile"`
	Landline                string           `json:"landline"`
	IssueAuthority          string           `json:"issueAuthority"`
	IssuerOrgRegionFull     string           `json:"issuerOrg_region_full"`
	IssuerOrgRegionAbbr     string           `json:"issuerOrg_region_abbr"`
	IssuerOrgISO2           string           `json:"issuerOrg_iso2"`
	NationalityISO2         string           `json:"nationality_iso2"`
	OptionalData            string           `json:"optionalData"`
	OptionalData2           string           `json:"optionalData2"`
	CustomData1             string           `json:"customdata1"`
	CustomData2             string           `json:"customdata2"`
	CustomData3             string           `json:"customdata3"`
	CustomData4             string           `json:"customdata4"`
	CustomData5             string           `json:"customdata5"`
	Block                   string           `json:"block"`
	Contract                string           `json:"contract"`
	Image                   []VaultImageData `json:"image"`
}

type VaultImageData struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Hash       string `json:"hash"`
	URL        string `json:"url"`
	CreateTime string `json:"createtime"`
}

type VaultTrainingStatusResponse struct {
	Status           string    `json:"status"`
	StartTime        string    `json:"startTime"`
	StatusChangeTime string    `json:"statusChangeTime"`
	LastSuccessTime  string    `json:"lastSuccessTime"`
	Error            *APIError `json:"error"`
}

// Initialize Vault API with an API key and region (US (default), EU)
func NewVaultAPI(apiKey, region string) (VaultAPI, error) {
	if apiKey == "" {
		return VaultAPI{}, errors.New("please provide an API key")
	}

	return VaultAPI{
		apiKey:      apiKey,
		apiEndpoint: endpointFromRegion(region, "vault"),
	}, nil
}

// ACTIONS

// Get a single vault entry
func (v *VaultAPI) Get(vault_id string) (response VaultItemResponse, err error) {
	if vault_id == "" {
		return VaultItemResponse{}, errors.New("vault entry ID required")
	}

	err = v.callAPI("get", VaultItemRequest{ID: vault_id}, &response)
	return
}

// List multiple vault entries with optional filter, sorting and paging arguments
func (v *VaultAPI) List(filter []string, orderby, sort string, limit, offset uint) (response VaultListResponse, err error) {
	if len(filter) > 5 {
		return VaultListResponse{}, errors.New("filter should be an array containing maximum of 5 filter statements")
	}

	err = v.callAPI("list", VaultListRequest{
		Filter:  filter,
		OrderBy: orderby,
		Sort:    sort,
		Limit:   limit,
		Offset:  offset,
	}, &response)
	return
}

// Update vault entry with new data
func (v *VaultAPI) Update(data VaultData) (response VaultSuccessResponse, err error) {
	if data.ID == "" {
		return VaultSuccessResponse{}, errors.New("vault entry ID required")
	}

	err = v.callAPI("update", data, &response)
	return
}

// Delete a single or multiple vault entries
func (v *VaultAPI) Delete(vault_id string) (response VaultSuccessResponse, err error) {
	if vault_id == "" {
		return VaultSuccessResponse{}, errors.New("vault entry ID required")
	}

	err = v.callAPI("delete", VaultItemRequest{ID: vault_id}, &response)
	return
}

// Add a document or face image into an existing vault entry
func (v *VaultAPI) AddImage(vault_id, image string, image_type uint) (response VaultImageResponse, err error) {
	if vault_id == "" {
		return VaultImageResponse{}, errors.New("vault entry ID required")
	}
	if image_type != 0 && image_type != 1 {
		return VaultImageResponse{}, errors.New("invalid image type, 0 or 1 accepted")
	}

	payload := map[string]interface{}{"id": vault_id, "type": image_type}

	if _, err := url.ParseRequestURI(image); err == nil {
		payload["imageurl"] = image
	} else if fileExists(image) {
		payload["image"] = base64File(image)
	} else if len(image) > 100 {
		payload["image"] = image
	} else {
		return VaultImageResponse{}, errors.New("invalid image, file not found, or malformed URL")
	}

	err = v.callAPI("addimage", payload, &response)
	return

}

// Delete an image from vault
func (v *VaultAPI) DeleteImage(vault_id, image_id string) (response VaultSuccessResponse, err error) {
	if vault_id == "" {
		return VaultSuccessResponse{}, errors.New("vault entry ID required")
	}
	if image_id == "" {
		return VaultSuccessResponse{}, errors.New("image ID required")
	}

	err = v.callAPI("deleteimage", map[string]interface{}{"id": vault_id, "imageid": image_id}, &response)
	return
}

// Search vault using a person's face image
func (v *VaultAPI) SearchFace(image string, maxEntry uint, threshold float32) (response VaultFaceSearchResponse, err error) {
	payload := map[string]interface{}{"maxentry": maxEntry, "threshold": threshold}

	if _, err := url.ParseRequestURI(image); err == nil {
		payload["imageurl"] = image
	} else if fileExists(image) {
		payload["image"] = base64File(image)
	} else if len(image) > 100 {
		payload["image"] = image
	} else {
		return VaultFaceSearchResponse{}, errors.New("invalid image, file not found or malformed URL")
	}

	err = v.callAPI("searchface", payload, &response)
	return
}

// Train vault for face search
func (v *VaultAPI) TrainFace() (response VaultSuccessResponse, err error) {
	err = v.callAPI("train", []string{}, &response)
	return
}

// Get vault training status
func (v *VaultAPI) TrainingStatus() (response VaultTrainingStatusResponse, err error) {
	err = v.callAPI("trainstatus", []string{}, &response)
	return
}

// PRIVATE

func (v *VaultAPI) callAPI(action string, request, result interface{}) error {
	var payload map[string]interface{}

	temp, _ := json.Marshal(request)
	json.Unmarshal(temp, &payload)

	payload["apikey"] = v.apiKey
	payload["client"] = "go-sdk"

	body, _ := json.Marshal(payload)

	if response, err := http.Post(fmt.Sprintf("%s/%s", v.apiEndpoint, action), "application/json", bytes.NewBuffer(body)); err != nil {
		return fmt.Errorf("failed to connect to API server: %s", err.Error())
	} else {
		body, _ := io.ReadAll(response.Body)
		json.Unmarshal(body, &result)

		return nil
	}
}
