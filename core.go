package idanalyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

type CoreAPI struct {
	apiKey      string
	apiEndpoint string
	config      coreConfig
}

type CoreResponse1Side struct {
	Error          *APIError              `json:"error,omitempty"`
	Result         *APIIdentityData       `json:"result,omitempty"`
	Confidence     *CoreConfidence        `json:"confidence,omitempty"`
	Face           *APIFaceData           `json:"face,omitempty"`
	Verification   *APIVerificationData   `json:"verification,omitempty"`
	Authentication *APIAuthenticationData `json:"authentication,omitempty"`
	AML            *AMLResponse           `json:"aml,omitempty"`
	Contract       *APIContractData       `json:"contract,omitempty"`
	VaultID        string                 `json:"vaultid,omitempty"`
	MatchRate      float32                `json:"matchrate,omitempty"`
	Output         string                 `json:"output,omitempty"`
	OutputFace     string                 `json:"outputface,omitempty"`
	Cropped        string                 `json:"cropped,omitempty"`
	CroppedFace    string                 `json:"croppedface,omitempty"`
	ExecutionTime  float64                `json:"executionTime"`
	ResponseID     string                 `json:"responseID"`
	Quota          uint                   `json:"quota,omitempty"`
	Credit         uint                   `json:"credit,omitempty"`
}

type CoreResponse2Sides struct {
	Error          *APIError              `json:"error,omitempty"`
	Result         *APIIdentityData       `json:"result,omitempty"`
	Confidence     *CoreConfidence        `json:"confidence,omitempty"`
	Face           *APIFaceData           `json:"face,omitempty"`
	Verification   *APIVerificationData   `json:"verification,omitempty"`
	Authentication *APIAuthenticationData `json:"authentication,omitempty"`
	AML            *AMLResponse           `json:"aml,omitempty"`
	Contract       *APIContractData       `json:"contract,omitempty"`
	VaultID        string                 `json:"vaultid,omitempty"`
	MatchRate      float32                `json:"matchrate,omitempty"`
	Output         []string               `json:"output,omitempty"`
	OutputFace     string                 `json:"outputface,omitempty"`
	Cropped        []string               `json:"cropped,omitempty"`
	CroppedFace    string                 `json:"croppedface,omitempty"`
	ExecutionTime  float64                `json:"executionTime"`
	ResponseID     string                 `json:"responseID"`
	Quota          uint                   `json:"quota,omitempty"`
	Credit         uint                   `json:"credit,omitempty"`
}

type CoreConfidence struct {
	DocumentNumber      float32 `json:"documentNumber"`
	PersonalNumber      float32 `json:"personalNumber"`
	FirstName           float32 `json:"firstName"`
	MiddleName          float32 `json:"middleName"`
	LastName            float32 `json:"lastName"`
	FullName            float32 `json:"fullName"`
	FirstNameLocal      float32 `json:"firstName_local"`
	MiddleNameLocal     float32 `json:"middleName_local"`
	LastNameLocal       float32 `json:"lastName_local"`
	FullNameLocal       float32 `json:"fullName_local"`
	DOB                 float32 `json:"dob"`
	DOBDay              float32 `json:"dob_day"`
	DOBMonth            float32 `json:"dob_month"`
	DOBYear             float32 `json:"dob_year"`
	Expiry              float32 `json:"expiry"`
	ExpiryDay           float32 `json:"expiry_day"`
	ExpiryMonth         float32 `json:"expiry_month"`
	ExpiryYear          float32 `json:"expiry_year"`
	Issued              float32 `json:"issued"`
	IssuedDay           float32 `json:"issued_day"`
	IssuedMonth         float32 `json:"issued_month"`
	IssuedYear          float32 `json:"issued_year"`
	DaysToExipry        float32 `json:"daysToExipry"`
	DaysFromIssue       float32 `json:"daysFromIssue"`
	Age                 float32 `json:"age"`
	Sex                 float32 `json:"sex"`
	Height              float32 `json:"height"`
	Weight              float32 `json:"weight"`
	HairColor           float32 `json:"hairColor"`
	EyeColor            float32 `json:"eyeColor"`
	Address1            float32 `json:"address1"`
	Address2            float32 `json:"address2"`
	Postcode            float32 `json:"postcode"`
	PlaceOfBirth        float32 `json:"placeOfBirth"`
	DocumentSide        float32 `json:"documentSide"`
	DocumentType        float32 `json:"documentType"`
	DocumentName        float32 `json:"documentName"`
	IssuerOrgRegionFull float32 `json:"issuerOrg_region_full"`
	IssuerOrgRegionAbbr float32 `json:"issuerOrg_region_abbr"`
	IssuerOrgFull       float32 `json:"issuerOrg_full"`
	IssuerOrgISO2       float32 `json:"issuerOrg_iso2"`
	IssuerOrgISO3       float32 `json:"issuerOrg_iso3"`
	NationalityFull     float32 `json:"nationality_full"`
	NationalityISO2     float32 `json:"nationality_iso2"`
	NationalityISO3     float32 `json:"nationality_iso3"`
	VehicleClass        float32 `json:"vehicleClass"`
	Restrictions        float32 `json:"restrictions"`
	Endorsement         float32 `json:"endorsement"`
	OptionalData        float32 `json:"optionalData"`
	OptionalData2       float32 `json:"optionalData2"`
	InternalID          float32 `json:"internalId"`
}

// Initialize Core API with an API key and region (US (default), EU)
func NewCoreAPI(apiKey, region string) (CoreAPI, error) {
	if apiKey == "" {
		return CoreAPI{}, errors.New("please provide an API key")
	}

	return CoreAPI{
		apiKey:      apiKey,
		apiEndpoint: endpointFromRegion(region, ""),
		config:      defaultCoreConfig,
	}, nil
}

// SETTERS

// Reset all API configurations except API key and region
func (c *CoreAPI) ResetConfig() {
	c.config = defaultCoreConfig
}

// Set OCR Accuracy: 0 = Fast, 1 = Balanced, 2 = Accurate (default)
func (c *CoreAPI) SetAccuracy(accuracy uint) {
	c.config.accuracy = accuracy
}

// Validate the document to check whether the document is authentic and has not been tampered, and set authentication module
// Authentication Module can be 1, 2 or quick
func (c *CoreAPI) EnableAuthentication(authenticate bool, authModule string) error {
	c.config.authenticate = authenticate

	if authModule != "1" && authModule != "2" && authModule != "quick" {
		return errors.New(`invalid authentication module; "1", "2" or "quick" accepted`)
	}
	c.config.authenticateModule = authModule

	return nil
}

// Scale down the uploaded image before sending to OCR engine
// Adjust this value to fine tune recognition accuracy on large full-resolution images
// Set to 0 to disable image resizing
func (c *CoreAPI) SetOCRImageResize(maxScale uint) error {
	if maxScale != 0 && (maxScale < 500 || maxScale > 4000) {
		return errors.New("invalid scale value; 0, or 500 to 4000 accepted")
	}
	c.config.ocrScaledown = maxScale

	return nil
}

// Set the minimum confidence score to consider faces being identical
// Value should be between 0 to 1; a higher value yields more-strict verification
func (c *CoreAPI) SetBiometricThreshold(threshold float32) error {
	if threshold <= 0 || threshold > 1 {
		return errors.New("invalid threshold value; float32 between 0 to 1 accepted")
	}
	c.config.biometricThreshold = threshold

	return nil
}

// Generate cropped image of document and/or face, and set output format [url, base64]
func (c *CoreAPI) EnableImageOutput(cropDocument, cropFace bool, outputFormat string) error {
	if outputFormat != "url" && outputFormat != "base64" {
		return errors.New(`invalid output format; "url" or "base64" accepted`)
	}
	c.config.outputImage = cropDocument
	c.config.outputFace = cropFace
	c.config.outputMode = outputFormat

	return nil
}

// Check if the names, document number and document type matches between the front and the back of the document when performing dual-side scan
// If any information mismatches error 14 will be thrown.
func (c *CoreAPI) EnableDualSideCheck(enabled bool) {
	c.config.dualSideCheck = enabled
}

// Check if the document is still valid based on its expiry date
func (c *CoreAPI) VerifyExpiry(enabled bool) {
	c.config.verifyExpiry = enabled
}

// Check if supplied document or personal number matches with document
func (c *CoreAPI) VerifyDocumentNumber(documentNumber string) {
	c.config.verifyDocumentNo = documentNumber
}

// Check if supplied name matches with document
func (c *CoreAPI) VerifyName(name string) {
	c.config.verifyName = name
}

// Check if supplied date of birth matches with document
func (c *CoreAPI) VerifyDOB(dob string) error {
	if _, err := time.Parse("2006/01/02", dob); err != nil {
		return errors.New("invalid birthday format (YYYY/MM/DD)")
	}
	c.config.verifyDOB = dob

	return nil
}

// Check if the document holder is aged between the given range
func (c *CoreAPI) VerifyAge(ageRange string) error {
	if matched, _ := regexp.MatchString(`^\d+-\d+$`, ageRange); !matched {
		return errors.New("invalid age range format (minAge-maxAge)")
	}
	c.config.verifyAge = ageRange

	return nil
}

// Check if supplied address matches with document
func (c *CoreAPI) VerifyAddress(address string) {
	c.config.verifyAddress = address
}

// Check if supplied postcode matches with document
func (c *CoreAPI) VerifyPostcode(postcode string) {
	c.config.verifyPostcode = postcode
}

// Check if the document was issued by specified countries, if not error code 10 will be thrown
// Separate multiple values with comma: For example "US,CA" would accept documents from United States and Canada
func (c *CoreAPI) RestrictCountry(countryCodes string) {
	c.config.country = countryCodes
}

// Check if the document was issued by specified state, if not error code 11 will be thrown
// Separate multiple values with comma: For example "CA,TX" would accept documents from California and Texas
func (c *CoreAPI) RestrictState(states string) {
	c.config.region = states
}

// Check if the document was one of the specified types, if not error code 12 will be thrown
// For example, "PD" would accept both passport and drivers license
func (c *CoreAPI) RestrictType(docTypes string) {
	c.config.docType = docTypes
}

// Disable Visual OCR and read data from AAMVA Barcodes only
func (c *CoreAPI) EnableBarcodeMode(enable bool) {
	c.config.barcodeMode = enable
}

// Check document holder's name and document number against ID Analyzer AML Database for sanctions, crimes and PEPs
func (c *CoreAPI) EnableAMLCheck(enable bool) {
	c.config.amlCheck = enable
}

// Specify the source databases to perform AML check, if left blank, all source databases will be checked
// Separate each database code with comma, for example: un_sc,us_ofac
// For full list of source databases and corresponding code visit AML API Overview
func (c *CoreAPI) SetAMLDatabase(databases string) {
	c.config.amlDatabase = databases
}

// By default, entities with identical name or document number will be considered a match even though their birthday or nationality may be unknown
// Enable this parameter to reduce false-positives by only matching entities with exact same nationality and birthday
func (c *CoreAPI) EnableAMLStrictMatch(enable bool) {
	c.config.amlStrictMatch = enable
}

// Save document image and parsed information in your secured vault
// You can list, search and update document entries in your vault through Vault API or web portal
func (c *CoreAPI) EnableVault(enabled, saveUnrecognized, noDuplicateImage, autoMergeDocument bool) {
	c.config.vaultSave = enabled
	c.config.vaultSaveUnrecognized = saveUnrecognized
	c.config.vaultNoDuplicate = noDuplicateImage
	c.config.vaultAutoMerge = autoMergeDocument
}

// Add up to 5 custom strings that will be associated with the vault entry, this can be useful for filtering and searching entries.
func (c *CoreAPI) SetVaultData(data1, data2, data3, data4, data5 string) {
	c.config.vaultCustomData1 = data1
	c.config.vaultCustomData2 = data2
	c.config.vaultCustomData3 = data3
	c.config.vaultCustomData4 = data4
	c.config.vaultCustomData5 = data5
}

// Generate legal document using data from user uploaded ID
//
// templateId: Contract Template ID displayed under web portal
// format: Output file format: PDF, DOCX or HTML
// prefillData: Associative array or JSON string, to autofill dynamic fields in contract template.
func (c *CoreAPI) GenerateContract(templateId, format string, prefillData map[string]string) error {
	if templateId == "" {
		return errors.New("invalid template ID")
	}
	if format != "PDF" && format != "DOCX" && format != "HTML" {
		return errors.New("invalid output file format")
	}
	c.config.contractGenerate = templateId
	c.config.contractFormat = format
	c.config.contractPrefillData = prefillData

	return nil
}

// ACTIONS

// Scan an ID document with Core API
func (c *CoreAPI) ScanFront(documentPrimary string) (CoreResponse1Side, error) {
	return c.scan1Side(documentPrimary, "", "", "")
}

// Scan an ID document with Core API; supply a face verification image
func (c *CoreAPI) ScanFrontFace(documentPrimary, biometricPhoto string) (CoreResponse1Side, error) {
	return c.scan1Side(documentPrimary, biometricPhoto, "", "")
}

// Scan an ID document with Core API; supply a face verification video
func (c *CoreAPI) ScanFrontVideo(documentPrimary, biometricVideo string) (CoreResponse1Side, error) {
	return c.scan1Side(documentPrimary, "", biometricVideo, "")
}

// Scan an ID document with Core API; supply a face verification video and video passcode
func (c *CoreAPI) ScanFrontVideoCustomPasscode(documentPrimary, biometricVideo, biometricVideoPasscode string) (CoreResponse1Side, error) {
	return c.scan1Side(documentPrimary, "", biometricVideo, biometricVideoPasscode)
}

// Scan both sides of an ID document with Core API
func (c *CoreAPI) ScanBoth(documentPrimary, documentSecondary string) (CoreResponse2Sides, error) {
	return c.scan2Sides(documentPrimary, documentSecondary, "", "", "")
}

// Scan both sides of an ID document with Core API; supply a face verification image
func (c *CoreAPI) ScanBothFace(documentPrimary, documentSecondary, biometricPhoto string) (CoreResponse2Sides, error) {
	return c.scan2Sides(documentPrimary, documentSecondary, biometricPhoto, "", "")
}

// Scan both sides of an ID document with Core API; supply a face verification video
func (c *CoreAPI) ScanBothVideo(documentPrimary, documentSecondary, biometricVideo string) (CoreResponse2Sides, error) {
	return c.scan2Sides(documentPrimary, documentSecondary, "", biometricVideo, "")
}

// Scan both sides of an ID document with Core API; supply a face verification video and video passcode
func (c *CoreAPI) ScanBothVideoCustomPasscode(documentPrimary, documentSecondary, biometricVideo, biometricVideoPasscode string) (CoreResponse2Sides, error) {
	return c.scan2Sides(documentPrimary, documentSecondary, "", biometricVideo, biometricVideoPasscode)
}

// PRIVATE

type coreConfig struct {
	accuracy              uint
	authenticate          bool
	authenticateModule    string
	ocrScaledown          uint
	outputImage           bool
	outputFace            bool
	outputMode            string
	dualSideCheck         bool
	verifyExpiry          bool
	verifyDocumentNo      string
	verifyName            string
	verifyDOB             string
	verifyAge             string
	verifyAddress         string
	verifyPostcode        string
	country               string
	region                string
	docType               string
	checkBlocklist        bool
	vaultSave             bool
	vaultSaveUnrecognized bool
	vaultNoDuplicate      bool
	vaultAutoMerge        bool
	vaultCustomData1      string
	vaultCustomData2      string
	vaultCustomData3      string
	vaultCustomData4      string
	vaultCustomData5      string
	barcodeMode           bool
	biometricThreshold    float32
	amlCheck              bool
	amlStrictMatch        bool
	amlDatabase           string
	contractGenerate      string
	contractFormat        string
	contractPrefillData   map[string]string
	client                string
}

type coreRequest struct {
	ApiKey                string            `json:"apikey"`
	Url                   string            `json:"url"`
	UrlBack               string            `json:"url_back"`
	FaceUrl               string            `json:"faceurl"`
	VideoUrl              string            `json:"videourl"`
	FileBase64            string            `json:"file_base64"`
	FileBackBase64        string            `json:"file_back_base64"`
	FaceBase64            string            `json:"face_base64"`
	VideoBase64           string            `json:"video_base64"`
	Passcode              string            `json:"passcode"`
	Accuracy              uint              `json:"accuracy"`
	Authenticate          bool              `json:"authenticate"`
	AuthenticateModule    string            `json:"authenticate_module"`
	OcrScaledown          uint              `json:"ocr_scaledown"`
	OutputImage           bool              `json:"outputimage"`
	OutputFace            bool              `json:"outputface"`
	OutputMode            string            `json:"outputmode"`
	DualSideCheck         bool              `json:"dualsidecheck"`
	VerifyExpiry          bool              `json:"verify_expiry"`
	VerifyDocumentNo      string            `json:"verify_documentno"`
	VerifyName            string            `json:"verify_name"`
	VerifyDOB             string            `json:"verify_dob"`
	VerifyAge             string            `json:"verify_age"`
	VerifyAddress         string            `json:"verify_address"`
	VerifyPostcode        string            `json:"verify_postcode"`
	Country               string            `json:"country"`
	Region                string            `json:"region"`
	DocType               string            `json:"type"`
	CheckBlocklist        bool              `json:"checkblocklist"`
	VaultSave             bool              `json:"vault_save"`
	VaultSaveUnrecognized bool              `json:"vault_saveunrecognized"`
	VaultNoDuplicate      bool              `json:"vault_noduplicate"`
	VaultAutoMerge        bool              `json:"vault_automerge"`
	VaultCustomData1      string            `json:"vault_customdata1"`
	VaultCustomData2      string            `json:"vault_customdata2"`
	VaultCustomData3      string            `json:"vault_customdata3"`
	VaultCustomData4      string            `json:"vault_customdata4"`
	VaultCustomData5      string            `json:"vault_customdata5"`
	BarcodeMode           bool              `json:"barcodemode"`
	BiometricThreshold    float32           `json:"biometric_threshold"`
	AmlCheck              bool              `json:"aml_check"`
	AmlStrictMatch        bool              `json:"aml_strict_match"`
	AmlDatabase           string            `json:"aml_database"`
	ContractGenerate      string            `json:"contract_generate"`
	ContractFormat        string            `json:"contract_format"`
	ContractPrefillData   map[string]string `json:"contract_prefill_data"`
	Client                string            `json:"client"`
}

var defaultCoreConfig = coreConfig{
	accuracy:              2,                   // high accuracy
	authenticate:          false,               // no auth
	authenticateModule:    "1",                 // moderate detail
	ocrScaledown:          2000,                // 2000 DPI
	outputImage:           false,               // don't output the card side(s)
	outputFace:            false,               // don't output the cropped face
	outputMode:            "url",               // outputs as URLs
	dualSideCheck:         false,               // only check front
	verifyExpiry:          true,                // verify expiration date
	verifyDocumentNo:      "",                  // don't check against specific value
	verifyName:            "",                  // don't check against specific value
	verifyDOB:             "",                  // don't check against specific value
	verifyAge:             "",                  // don't check against specific value
	verifyAddress:         "",                  // don't check against specific value
	verifyPostcode:        "",                  // don't check against specific value
	country:               "",                  // don't check against specific value
	region:                "",                  // don't check against specific value
	docType:               "",                  // don't check against specific value
	checkBlocklist:        false,               // don't check whether the ID is blocked
	vaultSave:             true,                // save image(s) in vault
	vaultSaveUnrecognized: false,               // don't save unrecognized image(s)
	vaultNoDuplicate:      false,               // save duplicates
	vaultAutoMerge:        false,               // don't collate duplicates
	vaultCustomData1:      "",                  // empty / unused
	vaultCustomData2:      "",                  // empty / unused
	vaultCustomData3:      "",                  // empty / unused
	vaultCustomData4:      "",                  // empty / unused
	vaultCustomData5:      "",                  // empty / unused
	barcodeMode:           false,               // check OCR as well as barcode
	biometricThreshold:    0.4,                 // succeed at 40% biometric confidence or higher
	amlCheck:              false,               // don't check AML
	amlStrictMatch:        false,               // loose AML match
	amlDatabase:           "",                  // no AML database set
	contractGenerate:      "",                  // don't generate contract
	contractFormat:        "",                  // no format set
	contractPrefillData:   map[string]string{}, // no prefilled data
	client:                "go-sdk",            // this request is coming from the Go SDK!
}

func (c *CoreAPI) scan1Side(documentPrimary, biometricPhoto, biometricVideo, biometricVideoPasscode string) (CoreResponse1Side, error) {
	var result CoreResponse1Side

	response, err := c.scan(documentPrimary, "", biometricPhoto, biometricVideo, biometricVideoPasscode)
	if err != nil {
		return CoreResponse1Side{}, err
	}

	body, _ := io.ReadAll(response.Body)
	json.Unmarshal(body, &result)

	if result.Error != nil && result.Error.Message != "" {
		return result, fmt.Errorf("%d: %s", result.Error.Code, result.Error.Message)
	}

	return result, nil
}

func (c *CoreAPI) scan2Sides(documentPrimary, documentSecondary, biometricPhoto, biometricVideo, biometricVideoPasscode string) (CoreResponse2Sides, error) {
	var result CoreResponse2Sides

	if documentSecondary == "" {
		return CoreResponse2Sides{}, errors.New("secondary document image required")
	}

	response, err := c.scan(documentPrimary, documentSecondary, biometricPhoto, biometricVideo, biometricVideoPasscode)
	if err != nil {
		return CoreResponse2Sides{}, err
	}

	body, _ := io.ReadAll(response.Body)
	json.Unmarshal(body, &result)

	if result.Error != nil && result.Error.Message != "" {
		return result, fmt.Errorf("%d: %s", result.Error.Code, result.Error.Message)
	}

	return result, nil
}

func (c *CoreAPI) scan(documentPrimary, documentSecondary, biometricPhoto, biometricVideo, biometricVideoPasscode string) (*http.Response, error) {
	payload := coreRequest{
		ApiKey:                c.apiKey,
		Accuracy:              c.config.accuracy,
		Authenticate:          c.config.authenticate,
		AuthenticateModule:    c.config.authenticateModule,
		OcrScaledown:          c.config.ocrScaledown,
		OutputImage:           c.config.outputImage,
		OutputFace:            c.config.outputFace,
		OutputMode:            c.config.outputMode,
		DualSideCheck:         c.config.dualSideCheck,
		VerifyExpiry:          c.config.verifyExpiry,
		VerifyDocumentNo:      c.config.verifyDocumentNo,
		VerifyName:            c.config.verifyName,
		VerifyDOB:             c.config.verifyDOB,
		VerifyAge:             c.config.verifyAge,
		VerifyAddress:         c.config.verifyAddress,
		VerifyPostcode:        c.config.verifyPostcode,
		Country:               c.config.country,
		Region:                c.config.region,
		DocType:               c.config.docType,
		CheckBlocklist:        c.config.checkBlocklist,
		VaultSave:             c.config.vaultSave,
		VaultSaveUnrecognized: c.config.vaultSaveUnrecognized,
		VaultNoDuplicate:      c.config.vaultNoDuplicate,
		VaultAutoMerge:        c.config.vaultAutoMerge,
		VaultCustomData1:      c.config.vaultCustomData1,
		VaultCustomData2:      c.config.vaultCustomData2,
		VaultCustomData3:      c.config.vaultCustomData3,
		VaultCustomData4:      c.config.vaultCustomData4,
		VaultCustomData5:      c.config.vaultCustomData5,
		BarcodeMode:           c.config.barcodeMode,
		BiometricThreshold:    c.config.biometricThreshold,
		AmlCheck:              c.config.amlCheck,
		AmlStrictMatch:        c.config.amlStrictMatch,
		AmlDatabase:           c.config.amlDatabase,
		ContractGenerate:      c.config.contractGenerate,
		ContractFormat:        c.config.contractFormat,
		ContractPrefillData:   c.config.contractPrefillData,
		Client:                c.config.client,
	}

	if documentPrimary == "" {
		return &http.Response{}, errors.New("primary document image required")
	}

	if _, err := url.ParseRequestURI(documentPrimary); err == nil {
		payload.Url = documentPrimary
	} else if fileExists(documentPrimary) {
		payload.FileBase64 = base64File(documentPrimary)
	} else if len(documentPrimary) > 100 {
		payload.FileBase64 = documentPrimary
	} else {
		return &http.Response{}, errors.New("invalid primary document image, file not found or malformed URL")
	}

	if documentSecondary != "" {
		if _, err := url.ParseRequestURI(documentSecondary); err == nil {
			payload.UrlBack = documentSecondary
		} else if fileExists(documentSecondary) {
			payload.FileBackBase64 = base64File(documentSecondary)
		} else if len(documentSecondary) > 100 {
			payload.FileBackBase64 = documentSecondary
		} else {
			return &http.Response{}, errors.New("invalid secondary document image, file not found or malformed URL")
		}
	}

	if biometricPhoto != "" {
		if _, err := url.ParseRequestURI(biometricPhoto); err == nil {
			payload.FaceUrl = biometricPhoto
		} else if fileExists(biometricPhoto) {
			payload.FaceBase64 = base64File(biometricPhoto)
		} else if len(biometricPhoto) > 100 {
			payload.FaceBase64 = biometricPhoto
		} else {
			return &http.Response{}, errors.New("invalid face image, file not found or malformed URL")
		}
	}

	if biometricVideo != "" {
		if _, err := url.ParseRequestURI(biometricVideo); err == nil {
			payload.VideoUrl = biometricVideo
		} else if fileExists(biometricVideo) {
			payload.VideoBase64 = base64File(biometricVideo)
		} else if len(biometricVideo) > 100 {
			payload.VideoBase64 = biometricVideo
		} else {
			return &http.Response{}, errors.New("invalid face video, file not found or malformed URL")
		}

		if matched, _ := regexp.MatchString(`^[0-9]{4}`, biometricVideoPasscode); !matched {
			return &http.Response{}, errors.New("please provide a 4 digit passcode for video biometric verification")
		} else {
			payload.Passcode = biometricVideoPasscode
		}
	}

	body, _ := json.Marshal(payload)

	if response, err := http.Post(c.apiEndpoint, "application/json", bytes.NewBuffer(body)); err != nil {
		return &http.Response{}, fmt.Errorf("failed to connect to API server: %s", err.Error())
	} else {
		return response, nil
	}
}
