package idanalyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type DocuPassAPI struct {
	apiKey      string
	apiEndpoint string
	companyName string
	config      docuPassConfig
}

type DocuPassIdentityResponse struct {
	Error     *APIError `json:"error,omitempty"`
	Reference string    `json:"reference"`
	Type      uint      `json:"type"`
	CustomID  string    `json:"customid"`
	URL       string    `json:"url"`
	QRCode    string    `json:"qrcode"`
	BaseURL   string    `json:"base_url"`
	HTML      string    `json:"html"`
	SMSSent   string    `json:"smssent"`
	Expiry    string    `json:"expiry"`
}

type DocuPassSignatureResponse struct {
	Error      *APIError `json:"error,omitempty"`
	Reference  string    `json:"reference"`
	CustomID   string    `json:"customid"`
	URL        string    `json:"url"`
	QRCode     string    `json:"qrcode"`
	BaseURL    string    `json:"base_url"`
	HTMLQRCode string    `json:"html_qrcode"`
	HTMLIFrame string    `json:"html_iframe"`
	SMSSent    string    `json:"smssent"`
	Expiry     string    `json:"expiry"`
}

type DocuPassIdentityCallback struct {
	Success        bool                        `json:"success"`
	Reference      string                      `json:"reference"`
	Hash           string                      `json:"hash"`
	CustomID       string                      `json:"customid"`
	FailReason     string                      `json:"failreason,omitempty"`
	FailCode       string                      `json:"failcode,omitempty"`
	Data           *APIIdentityData            `json:"data,omitempty"`
	Contract       *APIContractData            `json:"contract,omitempty"`
	Phone          *DocuPassCallbackPhone      `json:"phone,omitempty"`
	Face           *APIFaceData                `json:"face,omitempty"`
	Verification   *APIVerificationData        `json:"verification,omitempty"`
	Authentication *APIAuthenticationData      `json:"authentication,omitempty"`
	AML            []AMLResponseItem           `json:"aml,omitempty"`
	DocumentImage  []DocuPassCallbackImageData `json:"documentimage,omitempty"`
	FaceImage      []DocuPassCallbackImageData `json:"faceimage,omitempty"`
	VaultID        string                      `json:"vaultid,omitempty"`
}

type DocuPassSignatureCallback struct {
	Success    bool             `json:"success"`
	Reference  string           `json:"reference"`
	Hash       string           `json:"hash"`
	CustomID   string           `json:"customid"`
	FailReason string           `json:"failreason,omitempty"`
	FailCode   string           `json:"failcode,omitempty"`
	Contract   *APIContractData `json:"contract,omitempty"`
}

type DocuPassCallbackPhone struct {
	Number string `json:"number"`
	Type   string `json:"type"`
}

type DocuPassCallbackImageData struct {
	Side    string `json:"side,omitempty"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

type DocuPassValidationResponse struct {
	Error     *APIError `json:"error,omitempty"`
	Success   bool      `json:"success,omitempty"`
	Reference string    `json:"reference,omitempty"`
}

func NewDocuPassAPI(apiKey, companyName, region string) (DocuPassAPI, error) {
	if apiKey == "" {
		return DocuPassAPI{}, errors.New("please provide an API key")
	}

	if companyName == "" {
		return DocuPassAPI{}, errors.New("please provide your company name")
	}

	api := DocuPassAPI{
		apiKey:      apiKey,
		apiEndpoint: endpointFromRegion(region, "docupass"),
		companyName: companyName,
		config:      defaultDocuPassConfig,
	}

	return api, nil
}

// SETTERS

// Reset all API configurations except API key, company name, and region
func (d *DocuPassAPI) ResetConfig() {
	d.config = defaultDocuPassConfig
}

// Set max verification attempt per user
// Must be between 1 and 10, inclusive
func (d *DocuPassAPI) SetMaxAttempt(maxAttempt uint) error {
	if maxAttempt < 1 || maxAttempt > 10 {
		return errors.New("invalid max attempt, please specify integer between 1 to 10")
	}
	d.config.maxAttempt = maxAttempt

	return nil
}

// Set a custom string that will be sent back to your server's callback URL, and appended to redirection URLs as a query string
// It is useful for identifying your user within your database
// This value will be stored under docupass_customid under Vault
func (d *DocuPassAPI) SetCustomID(customID string) {
	d.config.customID = customID
}

// Display a custom message to the user in the beginning of verification
func (d *DocuPassAPI) SetWelcomeMessage(welcomeMessage string) {
	d.config.welcomeMessage = welcomeMessage
}

// Replace footer logo with your own logo
func (d *DocuPassAPI) SetLogo(url string) {
	d.config.logo = url
}

// Hide all branding logo
func (d *DocuPassAPI) HideBrandingLogo(hide bool) {
	d.config.noBranding = hide
}

// Replace DocuPass page content with your own HTML and CSS
// You can download the HTML/CSS template from DocuPass API Reference page
func (d *DocuPassAPI) SetCustomHTML(url string) {
	d.config.customHtmlUrl = url
}

// DocuPass automatically detects user device language and display corresponding language
// Set this parameter to override automatic language detection
func (d *DocuPassAPI) SetLanguage(lang string) {
	d.config.language = lang
}

// Set server-side callback/webhook URL to receive verification results
func (d *DocuPassAPI) SetCallbackUrl(callback string) error {
	if uri, err := url.ParseRequestURI(callback); err != nil {
		return errors.New("invalid URL format")
	} else if ip := net.ParseIP(uri.Host); (ip != nil && isPrivateIP(ip)) || strings.ToLower(uri.Host) == "localhost" {
		return errors.New("invalid URL, the host does not appear to be a remote host")
	} else if uri.Scheme != "http" && uri.Scheme != "https" {
		return errors.New("invalid URL, only http and https protocols are allowed")
	}
	d.config.callbackUrl = callback

	return nil
}

// Redirect client browser to set URLs after verification
// DocuPass reference code and customid will be appended to the end of URL, e.g. https://www.example.com/success.php?reference=XXXXXXXX&customid=XXXXXXXX
func (d *DocuPassAPI) SetRedirectURL(successUrl, failUrl string) error {
	if _, err := url.ParseRequestURI(successUrl); err != nil && successUrl != "" {
		return errors.New("invalid URL format for success URL")
	}
	if _, err := url.ParseRequestURI(failUrl); err != nil && failUrl != "" {
		return errors.New("invalid URL format for fail URL")
	}
	d.config.successRedir = successUrl
	d.config.failRedir = failUrl

	return nil
}

// Validate the document to check whether the document is authentic and has not been tampered
func (d *DocuPassAPI) EnableAuthentication(enabled bool, module string, minScore float32) error {
	if !enabled {
		d.config.authenticateMinScore = 0
	} else {
		if minScore < 0 || minScore > 1 {
			return errors.New("invalid minimum score; please specify float between 0 to 1")
		}
		if module != "1" && module != "2" && module != "quick" {
			return errors.New(`invalid authentication module; "1", "2" or "quick" accepted`)
		}

		d.config.authenticateModule = module
		d.config.authenticateMinScore = minScore
	}

	return nil
}

// Whether users will be required to submit a selfie photo or record selfie video for facial verification
func (d *DocuPassAPI) EnableFaceVerification(enabled bool, verificationType uint, threshold float32) error {
	if !enabled {
		d.config.biometric = 0
	} else {
		if threshold < 0 || threshold > 1 {
			return errors.New("invalid threshold; please specify float between 0 to 1")
		}
		if verificationType != 1 && verificationType != 2 {
			return errors.New("invalid verification type; use 1 for photo verification, 2 for video verification")
		}

		d.config.biometric = verificationType
		d.config.biometricThreshold = threshold
	}

	return nil
}

// Enabling this parameter will allow multiple users to verify their identity through the same URL
// A new DocuPass reference code will be generated for each user automatically
func (d *DocuPassAPI) SetReusable(enabled bool) {
	d.config.reusable = enabled
}

// Enable or disable returning user uploaded document and/or face image in callback, and image data format
func (d *DocuPassAPI) SetCallbackImage(sendDocument, sendFace bool, format uint) {
	d.config.returnDocumentImage = sendDocument
	d.config.returnFaceImage = sendFace
	if format == 0 {
		d.config.returnType = 0
	} else {
		d.config.returnType = 1
	}
}

// Configure QR code generated for DocuPass Mobile and Live Mobile
func (d *DocuPassAPI) SetQRCodeFormat(fore, back string, size, margin uint) error {
	if _, err := strconv.ParseUint(fore, 16, 0); err != nil || len(fore) != 6 {
		return errors.New("invalid foreground color HEX code")
	}
	if _, err := strconv.ParseUint(back, 16, 0); err != nil || len(back) != 6 {
		return errors.New("invalid background color HEX code")
	}
	if size < 1 || size > 50 {
		return errors.New("invalid image size; must be between 1 and 50")
	}
	if margin < 1 || margin > 50 {
		return errors.New("invalid margin; must be between 1 and 50")
	}
	d.config.qrColor = fore
	d.config.qrBgColor = back
	d.config.qrSize = size
	d.config.qrMargin = margin

	return nil
}

// Check if the names, document number and document type matches
// between the front and the back of the document when performing dual-side scan
// If any information mismatches error 14 will be thrown
func (d *DocuPassAPI) EnableDualSideCheck(enabled bool) {
	d.config.dualSideCheck = enabled
}

// Check document holder's name and document number against ID Analyzer AML Database for sanctions, crimes and PEPs
func (d *DocuPassAPI) EnableAMLCheck(enabled bool) {
	d.config.amlCheck = enabled
}

// Specify the source databases to perform AML check
// If left blank, all source databases will be checked
// Separate each database code with comma, for example: un_sc,us_ofac
// For full list of source databases and corresponding code visit AML API Overview
func (d *DocuPassAPI) SetAMLDatabase(databases string) {
	d.config.amlDatabase = databases
}

// By default, entities with identical name or document number will be considered a match even though their birthday or nationality may be unknown
// Enable this parameter to reduce false-positives by only matching entities with exact same nationality and birthday
func (d *DocuPassAPI) EnableAMLStrictMatch(enabled bool) {
	d.config.amlStrictMatch = enabled
}

// Whether to ask user to enter a phone number for verification
// DocuPass supports both mobile or landline number verification
// Verified phone number will be returned in callback JSON
func (d *DocuPassAPI) EnablePhoneVerification(enabled bool) {
	d.config.phoneVerification = enabled
}

// DocuPass will send SMS to this number containing DocuPass link to perform identity verification
// the number provided will be automatically considered as verified if user completes identity verification
// If an invalid or unreachable number is provided error 1050 will be thrown
// You should add your own thresholding mechanism to prevent abuse as you will be charged 1 quota to send the SMS
func (d *DocuPassAPI) SMSVerificationLink(number string) {
	d.config.smsVerificationLink = number
}

// DocuPass will send SMS to this number containing DocuPass link to review and sign legal document
func (d *DocuPassAPI) SMSContractLink(number string) {
	d.config.smsContractLink = number
}

// DocuPass will attempt to verify this phone number as part of the identity verification process
// Both mobile or landline are supported
// Users will not be able to enter their own numbers or change the provided number
func (d *DocuPassAPI) VerifyPhone(number string) {
	d.config.verifyPhone = number
}

// Check if the document is still valid based on its expiry date
func (d *DocuPassAPI) VerifyExpiry(verify bool) {
	d.config.verifyExpiry = verify
}

// Check if supplied document or personal number matches with document
func (d *DocuPassAPI) VerifyDocumentNumber(number string) {
	d.config.verifyDocumentNo = number
}

// Check if supplied name matches with document
func (d *DocuPassAPI) VerifyName(name string) {
	d.config.verifyName = name
}

// Check if supplied date of birth matches with document
func (d *DocuPassAPI) VerifyDOB(date string) error {
	if _, err := time.Parse("2006/01/02", date); err != nil && date != "" {
		return errors.New("invalid birthday format (YYYY/MM/DD)")
	}
	d.config.verifyDOB = date

	return nil
}

// Check if the document holder is aged between the given range
func (d *DocuPassAPI) VerifyAge(ageRange string) error {
	if matched, _ := regexp.MatchString(`^\d+-\d+$`, ageRange); !matched && ageRange != "" {
		return errors.New("invalid age range format (minAge-maxAge)")
	}
	d.config.verifyAge = ageRange

	return nil
}

// Check if supplied address matches with document
func (d *DocuPassAPI) VerifyAddress(address string) {
	d.config.verifyAddress = address
}

// Check if supplied postcode matches with document
func (d *DocuPassAPI) VerifyPostcode(postcode string) {
	d.config.verifyPostcode = postcode
}

// Check if the document was issued by specified countries
// If not error code 10 will be thrown
// Separate multiple values with comma
// For example "US,CA" would accept documents from United States and Canada.
func (d *DocuPassAPI) RestrictCountry(countryCodes string) {
	d.config.documentCountry = countryCodes
}

// Check if the document was issued by specified state
// If not error code 11 will be thrown
// Separate multiple values with comma
// For example "CA,TX" would accept documents from California and Texas.
func (d *DocuPassAPI) RestrictState(states string) {
	d.config.documentRegion = states
}

// Only accept document of specified types.
func (d *DocuPassAPI) RestrictType(documentType string) {
	d.config.documentType = documentType
}

// Save document image and parsed information in your secured vault
// You can list, search and update document entries in your vault through Vault API or web portal
func (d *DocuPassAPI) EnableVault(enabled bool) {
	d.config.vaultSave = enabled
}

// Generate legal document using data from user uploaded ID
// templateID: Contract Template ID displayed under web portal
// format: Output file format: PDF, DOCX or HTML
// prefillData: JSON-encodable data to autofill dynamic fields in contract template
func (d *DocuPassAPI) GenerateContract(templateID, format string, prefillData map[string]interface{}) error {
	if templateID == "" {
		return errors.New("invalid template ID")
	}
	if format != "PDF" && format != "DOCX" && format != "HTML" {
		return errors.New(`invalid format; must be "PDF", "DOCX", or "HTML"`)
	}
	d.config.contractGenerate = templateID
	d.config.contractSign = ""
	d.config.contractFormat = format
	d.config.contractPrefillData = prefillData

	return nil
}

// Have user review and sign autofilled legal document after successful identity verification
// templateID: Contract Template ID displayed under web portal
// format: Output file format: PDF, DOCX or HTML
// prefillData: JSON-encodable data to autofill dynamic fields in contract template
func (d *DocuPassAPI) SignContract(templateID, format string, prefillData map[string]interface{}) error {
	if templateID == "" {
		return errors.New("invalid template ID")
	}
	if format != "PDF" && format != "DOCX" && format != "HTML" {
		return errors.New(`invalid format; must be "PDF", "DOCX", or "HTML"`)
	}
	d.config.contractGenerate = ""
	d.config.contractSign = templateID
	d.config.contractFormat = format
	d.config.contractPrefillData = prefillData

	return nil
}

// ACTIONS

// Create a DocuPass identity verification session for embedding in web page as iframe
func (d *DocuPassAPI) CreateIFrame() (DocuPassIdentityResponse, error) {
	return d.create(0)
}

// Create a DocuPass identity verification session for users to open on mobile phone, or embedding in mobile app
func (d *DocuPassAPI) CreateMobile() (DocuPassIdentityResponse, error) {
	return d.create(1)
}

// Create a DocuPass identity verification session for users to open in any browser
func (d *DocuPassAPI) CreateRedirection() (DocuPassIdentityResponse, error) {
	return d.create(2)
}

// Create a DocuPass Live Mobile identity verification session for users to open on mobile phone
func (d *DocuPassAPI) CreateLiveMobile() (DocuPassIdentityResponse, error) {
	return d.create(3)
}

// Create a DocuPass signature session for user to review and sign legal document without identity verification
// templateID: Contract Template ID displayed under web portal
// format: Output file format: PDF, DOCX or HTML
// prefillData: JSON-encodable data to autofill dynamic fields in contract template
func (d *DocuPassAPI) CreateSignature(templateID, format string, prefillData map[string]interface{}) (DocuPassSignatureResponse, error) {
	payload := d.requestFromConfig()
	payload.TemplateID = templateID
	payload.ContractFormat = format
	payload.ContractPrefillData = prefillData

	body, _ := json.Marshal(payload)

	if response, err := http.Post(fmt.Sprintf("%s/sign", d.apiEndpoint), "application/json", bytes.NewBuffer(body)); err != nil {
		return DocuPassSignatureResponse{}, fmt.Errorf("failed to connect to API server: %s", err.Error())
	} else {
		var result DocuPassSignatureResponse

		body, _ := io.ReadAll(response.Body)
		json.Unmarshal(body, &result)

		if result.Error != nil && result.Error.Message != "" {
			return result, fmt.Errorf("%d: %s", result.Error.Code, result.Error.Message)
		}

		return result, nil
	}
}

//
func (d *DocuPassAPI) Validate(reference, hash string) (bool, error) {
	payload := map[string]string{
		"apikey":    d.apiKey,
		"reference": reference,
		"hash":      hash,
	}

	body, _ := json.Marshal(payload)

	if response, err := http.Post(fmt.Sprintf("%s/validate", d.apiEndpoint), "application/json", bytes.NewBuffer(body)); err != nil {
		return false, fmt.Errorf("failed to connect to API server: %s", err.Error())
	} else {
		var result DocuPassValidationResponse

		body, _ := io.ReadAll(response.Body)
		json.Unmarshal(body, &result)

		return result.Success, nil
	}
}

// PRIVATE

type docuPassConfig struct {
	amlCheck             bool
	amlDatabase          string
	amlStrictMatch       bool
	authenticateMinScore float32
	authenticateModule   string
	biometric            uint
	biometricThreshold   float32
	callbackUrl          string
	contractFormat       string
	contractGenerate     string
	contractPrefillData  map[string]interface{}
	contractSign         string
	cropDocument         bool
	customHtmlUrl        string
	customID             string
	documentCountry      string
	documentRegion       string
	documentType         string
	dualSideCheck        bool
	failRedir            string
	language             string
	logo                 string
	maxAttempt           uint
	noBranding           bool
	phoneVerification    bool
	qrBgColor            string
	qrColor              string
	qrMargin             uint
	qrSize               uint
	returnDocumentImage  bool
	returnFaceImage      bool
	returnType           uint
	reusable             bool
	smsContractLink      string
	smsVerificationLink  string
	successRedir         string
	vaultSave            bool
	verifyAddress        string
	verifyAge            string
	verifyDOB            string
	verifyDocumentNo     string
	verifyExpiry         bool
	verifyName           string
	verifyPhone          string
	verifyPostcode       string
	welcomeMessage       string
}

type docuPassRequest struct {
	ApiKey               string                 `json:"apikey"`
	CompanyName          string                 `json:"companyname"`
	AMLCheck             bool                   `json:"aml_check"`
	AMLDatabase          string                 `json:"aml_database"`
	AMLStrictMatch       bool                   `json:"aml_strict_match"`
	AuthenticateMinScore float32                `json:"authenticate_minscore"`
	AuthenticateModule   string                 `json:"authenticate_module"`
	Biometric            uint                   `json:"biometric"`
	BiometricThreshold   float32                `json:"biometric_threshold"`
	CallbackUrl          string                 `json:"callbackurl"`
	ContractFormat       string                 `json:"contract_format"`
	ContractGenerate     string                 `json:"contract_generate"`
	ContractPrefillData  map[string]interface{} `json:"contract_prefill_data"`
	ContractSign         string                 `json:"contract_sign"`
	CropDocument         bool                   `json:"crop_document"`
	CustomHtmlUrl        string                 `json:"customhtmlurl"`
	CustomID             string                 `json:"customid"`
	DocumentBase64       string                 `json:"document_base64,omitempty"`
	DocumentBackBase64   string                 `json:"document_back_base64,omitempty"`
	DocumentBackURL      string                 `json:"document_back_url,omitempty"`
	DocumentCountry      string                 `json:"documentcountry"`
	DocumentRegion       string                 `json:"documentregion"`
	DocumentType         string                 `json:"documenttype"`
	DocumentURL          string                 `json:"document_url,omitempty"`
	DualSideCheck        bool                   `json:"dualsidecheck"`
	FaceBase64           string                 `json:"face_base64,omitempty"`
	FaceURL              string                 `json:"face_url,omitempty"`
	FailRedir            string                 `json:"failredir"`
	Language             string                 `json:"language"`
	Logo                 string                 `json:"logo"`
	MaxAttempt           uint                   `json:"maxattempt"`
	NoBranding           bool                   `json:"nobranding"`
	PhoneVerification    bool                   `json:"phoneverification"`
	QRBgColor            string                 `json:"qr_bgcolor"`
	QRColor              string                 `json:"qr_color"`
	QRMargin             uint                   `json:"qr_margin"`
	QRSize               uint                   `json:"qr_size"`
	ReturnDocumentImage  bool                   `json:"return_documentimage"`
	ReturnFaceImage      bool                   `json:"return_faceimage"`
	ReturnType           uint                   `json:"return_type"`
	Reusable             bool                   `json:"reusable"`
	SMSContractLink      string                 `json:"sms_contract_link"`
	SMSVerificationLink  string                 `json:"sms_verification_link"`
	SuccessRedir         string                 `json:"successredir"`
	TemplateID           string                 `json:"template_id,omitempty"`
	Type                 uint                   `json:"type"`
	VaultSave            bool                   `json:"vault_save"`
	VerifyAddress        string                 `json:"verify_address"`
	VerifyAge            string                 `json:"verify_age"`
	VerifyDOB            string                 `json:"verify_dob"`
	VerifyDocumentNo     string                 `json:"verify_documentno"`
	VerifyExpiry         bool                   `json:"verify_expiry"`
	VerifyName           string                 `json:"verify_name"`
	VerifyPhone          string                 `json:"verify_phone"`
	VerifyPostcode       string                 `json:"verify_postcode"`
	WelcomeMessage       string                 `json:"welcomemessage"`
	Client               string                 `json:"client"`
}

var defaultDocuPassConfig = docuPassConfig{
	amlCheck:             false,
	amlDatabase:          "",
	amlStrictMatch:       false,
	authenticateMinScore: 0,
	authenticateModule:   "2",
	biometric:            0,
	biometricThreshold:   0.4,
	callbackUrl:          "",
	contractFormat:       "",
	contractGenerate:     "",
	contractPrefillData:  map[string]interface{}{},
	contractSign:         "",
	cropDocument:         false,
	customHtmlUrl:        "",
	customID:             "",
	documentCountry:      "",
	documentRegion:       "",
	documentType:         "",
	dualSideCheck:        false,
	failRedir:            "",
	language:             "",
	logo:                 "",
	maxAttempt:           1,
	noBranding:           false,
	phoneVerification:    false,
	qrBgColor:            "",
	qrColor:              "",
	qrMargin:             1,
	qrSize:               5,
	returnDocumentImage:  true,
	returnFaceImage:      true,
	returnType:           1,
	reusable:             false,
	smsContractLink:      "",
	smsVerificationLink:  "",
	successRedir:         "",
	vaultSave:            true,
	verifyAddress:        "",
	verifyAge:            "",
	verifyDOB:            "",
	verifyDocumentNo:     "",
	verifyExpiry:         false,
	verifyName:           "",
	verifyPhone:          "",
	verifyPostcode:       "",
	welcomeMessage:       "",
}

func (d *DocuPassAPI) requestFromConfig() docuPassRequest {
	return docuPassRequest{
		ApiKey:               d.apiKey,
		CompanyName:          d.companyName,
		AMLCheck:             d.config.amlCheck,
		AMLDatabase:          d.config.amlDatabase,
		AMLStrictMatch:       d.config.amlStrictMatch,
		AuthenticateMinScore: d.config.authenticateMinScore,
		AuthenticateModule:   d.config.authenticateModule,
		Biometric:            d.config.biometric,
		BiometricThreshold:   d.config.biometricThreshold,
		CallbackUrl:          d.config.callbackUrl,
		ContractFormat:       d.config.contractFormat,
		ContractGenerate:     d.config.contractGenerate,
		ContractPrefillData:  d.config.contractPrefillData,
		ContractSign:         d.config.contractSign,
		CropDocument:         d.config.cropDocument,
		CustomHtmlUrl:        d.config.customHtmlUrl,
		CustomID:             d.config.customID,
		DocumentCountry:      d.config.documentCountry,
		DocumentRegion:       d.config.documentRegion,
		DocumentType:         d.config.documentType,
		DualSideCheck:        d.config.dualSideCheck,
		FailRedir:            d.config.failRedir,
		Language:             d.config.language,
		Logo:                 d.config.logo,
		MaxAttempt:           d.config.maxAttempt,
		NoBranding:           d.config.noBranding,
		PhoneVerification:    d.config.phoneVerification,
		QRBgColor:            d.config.qrBgColor,
		QRColor:              d.config.qrColor,
		QRMargin:             d.config.qrMargin,
		QRSize:               d.config.qrSize,
		ReturnDocumentImage:  d.config.returnDocumentImage,
		ReturnFaceImage:      d.config.returnFaceImage,
		ReturnType:           d.config.returnType,
		Reusable:             d.config.reusable,
		SMSContractLink:      d.config.smsContractLink,
		SMSVerificationLink:  d.config.smsVerificationLink,
		SuccessRedir:         d.config.successRedir,
		VaultSave:            d.config.vaultSave,
		VerifyAddress:        d.config.verifyAddress,
		VerifyAge:            d.config.verifyAge,
		VerifyDOB:            d.config.verifyDOB,
		VerifyDocumentNo:     d.config.verifyDocumentNo,
		VerifyExpiry:         d.config.verifyExpiry,
		VerifyName:           d.config.verifyName,
		VerifyPhone:          d.config.verifyPhone,
		VerifyPostcode:       d.config.verifyPostcode,
		WelcomeMessage:       d.config.welcomeMessage,
		Client:               "go-sdk",
	}
}

func (d *DocuPassAPI) create(mode uint) (DocuPassIdentityResponse, error) {
	payload := d.requestFromConfig()
	payload.Type = mode

	body, _ := json.Marshal(payload)

	if response, err := http.Post(fmt.Sprintf("%s/create", d.apiEndpoint), "application/json", bytes.NewBuffer(body)); err != nil {
		return DocuPassIdentityResponse{}, fmt.Errorf("failed to connect to API server: %s", err.Error())
	} else {
		var result DocuPassIdentityResponse

		body, _ := io.ReadAll(response.Body)
		json.Unmarshal(body, &result)

		if result.Error != nil && result.Error.Message != "" {
			return result, fmt.Errorf("%d: %s", result.Error.Code, result.Error.Message)
		}

		return result, nil
	}
}
