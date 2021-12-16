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

type VaultRequest map[string]interface{}

type VaultResponse map[string]interface{}

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
func (v *VaultAPI) Get(vault_id string) (VaultResponse, error) {
	if vault_id == "" {
		return nil, errors.New("vault entry ID required")
	}

	return v.callAPI("get", VaultRequest{"id": vault_id})
}

// List multiple vault entries with optional filter, sorting and paging arguments
func (v *VaultAPI) List(filter []string, orderby, sort string, limit, offset uint) (VaultResponse, error) {
	if len(filter) > 5 {
		return nil, errors.New("filter should be an array containing maximum of 5 filter statements")
	}

	return v.callAPI("list", VaultRequest{
		"filter":  filter,
		"orderby": orderby,
		"sort":    sort,
		"limit":   limit,
		"offset":  offset,
	})
}

// Update vault entry with new data
func (v *VaultAPI) Update(vault_id string, data VaultRequest) (VaultResponse, error) {
	if vault_id == "" {
		return nil, errors.New("vault entry ID required")
	}
	if len(data) < 1 {
		return nil, errors.New("data required")
	}
	data["id"] = vault_id

	return v.callAPI("update", data)
}

// Delete a single or multiple vault entries
func (v *VaultAPI) Delete(vault_id string) (VaultResponse, error) {
	if vault_id == "" {
		return nil, errors.New("vault entry ID required")
	}

	return v.callAPI("delete", VaultRequest{"id": vault_id})
}

// Add a document or face image into an existing vault entry
func (v *VaultAPI) AddImage(vault_id, image string, image_type uint) (VaultResponse, error) {
	if vault_id == "" {
		return nil, errors.New("vault entry ID required")
	}
	if image_type != 0 && image_type != 1 {
		return nil, errors.New("invalid image type, 0 or 1 accepted")
	}

	payload := VaultRequest{"id": vault_id, "type": image_type}

	if _, err := url.ParseRequestURI(image); err == nil {
		payload["imageurl"] = image
	} else if fileExists(image) {
		payload["image"] = base64File(image)
	} else if len(image) > 100 {
		payload["image"] = image
	} else {
		return VaultResponse{}, errors.New("invalid image, file not found or malformed URL")
	}

	return v.callAPI("addimage", payload)

}

// Delete an image from vault
func (v *VaultAPI) DeleteImage(vault_id, image_id string) (VaultResponse, error) {
	if vault_id == "" {
		return nil, errors.New("vault entry ID required")
	}
	if image_id == "" {
		return nil, errors.New("image ID required")
	}

	return v.callAPI("deleteimage", VaultRequest{"id": vault_id, "imageid": image_id})
}

// Search vault using a person's face image
func (v *VaultAPI) SearchFace(image string, maxEntry uint, threshold float32) (VaultResponse, error) {
	payload := VaultRequest{"maxentry": maxEntry, "threshold": threshold}

	if _, err := url.ParseRequestURI(image); err == nil {
		payload["imageurl"] = image
	} else if fileExists(image) {
		payload["image"] = base64File(image)
	} else if len(image) > 100 {
		payload["image"] = image
	} else {
		return VaultResponse{}, errors.New("invalid image, file not found or malformed URL")
	}

	return v.callAPI("searchface", payload)
}

// Train vault for face search
func (v *VaultAPI) TrainFace() (VaultResponse, error) {
	return v.callAPI("train", VaultRequest{})
}

// Get vault training status
func (v *VaultAPI) TrainingStatus() (VaultResponse, error) {
	return v.callAPI("trainstatus", VaultRequest{})
}

// PRIVATE

func (v *VaultAPI) callAPI(action string, payload VaultRequest) (VaultResponse, error) {
	payload["apikey"] = v.apiKey
	payload["client"] = "go-sdk"

	body, _ := json.Marshal(payload)

	if response, err := http.Post(fmt.Sprintf("%s/%s", v.apiEndpoint, action), "application/json", bytes.NewBuffer(body)); err != nil {
		return VaultResponse{}, fmt.Errorf("failed to connect to API server: %s", err.Error())
	} else {
		var result VaultResponse

		body, _ := io.ReadAll(response.Body)
		json.Unmarshal(body, &result)

		if err, ok := result["error"]; ok && err.(map[string]interface{})["message"] != "" {
			return result, fmt.Errorf("%d: %s", err.(map[string]interface{})["code"], err.(map[string]interface{})["message"])
		}

		return result, nil
	}
}
