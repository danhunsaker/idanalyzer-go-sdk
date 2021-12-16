package idanalyzer

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"reflect"
)

type APIError struct {
	Code    uint   `json:"code"`
	Message string `json:"message"`
}

type APIIdentityData struct {
	DocumentNumber      string `json:"documentNumber"`
	PersonalNumber      string `json:"personalNumber"`
	FirstName           string `json:"firstName"`
	MiddleName          string `json:"middleName"`
	LastName            string `json:"lastName"`
	FullName            string `json:"fullName"`
	FirstNameLocal      string `json:"firstName_local"`
	MiddleNameLocal     string `json:"middleName_local"`
	LastNameLocal       string `json:"lastName_local"`
	FullNameLocal       string `json:"fullName_local"`
	DOB                 string `json:"dob"`
	DOBDay              uint   `json:"dob_day"`
	DOBMonth            uint   `json:"dob_month"`
	DOBYear             uint   `json:"dob_year"`
	Expiry              string `json:"expiry"`
	ExpiryDay           uint   `json:"expiry_day"`
	ExpiryMonth         uint   `json:"expiry_month"`
	ExpiryYear          uint   `json:"expiry_year"`
	Issued              string `json:"issued"`
	IssuedDay           uint   `json:"issued_day"`
	IssuedMonth         uint   `json:"issued_month"`
	IssuedYear          uint   `json:"issued_year"`
	DaysToExipry        uint   `json:"daysToExipry"`
	DaysFromIssue       uint   `json:"daysFromIssue"`
	Age                 uint   `json:"age"`
	Sex                 string `json:"sex"`
	Height              string `json:"height"`
	Weight              string `json:"weight"`
	HairColor           string `json:"hairColor"`
	EyeColor            string `json:"eyeColor"`
	Address1            string `json:"address1"`
	Address2            string `json:"address2"`
	Postcode            string `json:"postcode"`
	PlaceOfBirth        string `json:"placeOfBirth"`
	DocumentSide        string `json:"documentSide"`
	DocumentType        string `json:"documentType"`
	DocumentName        string `json:"documentName"`
	IssuerOrgRegionFull string `json:"issuerOrg_region_full"`
	IssuerOrgRegionAbbr string `json:"issuerOrg_region_abbr"`
	IssuerOrgFull       string `json:"issuerOrg_full"`
	IssuerOrgISO2       string `json:"issuerOrg_iso2"`
	IssuerOrgISO3       string `json:"issuerOrg_iso3"`
	NationalityFull     string `json:"nationality_full"`
	NationalityISO2     string `json:"nationality_iso2"`
	NationalityISO3     string `json:"nationality_iso3"`
	VehicleClass        string `json:"vehicleClass"`
	Restrictions        string `json:"restrictions"`
	Endorsement         string `json:"endorsement"`
	OptionalData        string `json:"optionalData"`
	OptionalData2       string `json:"optionalData2"`
	InternalID          string `json:"internalId"`
}

type APIContractData struct {
	DocumentURL string `json:"document_url,omitempty"`
	Error       string `json:"error,omitempty"`
}

type APIFaceData struct {
	IsIdentical  bool    `json:"isIdentical"`
	Confidence   float32 `json:"confidence"`
	Error        uint    `json:"error,omitempty"`
	ErrorMessage string  `json:"error_message,omitempty"`
}

type APIVerificationData struct {
	Passed bool                  `json:"passed"`
	Result APIVerificationResult `json:"result"`
}

type APIVerificationResult struct {
	CheckDigit     bool `json:"checkdigit"`
	Face           bool `json:"face"`
	NotExpired     bool `json:"notexpired"`
	DocumentNumber bool `json:"documentNumber"`
	Name           bool `json:"name"`
	Age            bool `json:"age"`
	DOB            bool `json:"dob"`
	Address        bool `json:"address"`
	Postcode       bool `json:"postcode"`
	CCCode         bool `json:"cccode"`
}

type APIAuthenticationData struct {
	Score     float32                     `json:"score"`
	Breakdown *APIAuthenticationBreakdown `json:"breakdown"`
	Warning   []string                    `json:"warning"`
}

type APIAuthenticationBreakdown struct {
	DataVisibility       *APIAuthenticationBreakdownSection `json:"data_visibility"`
	ImageQuality         *APIAuthenticationBreakdownSection `json:"image_quality"`
	FeatureReferencing   *APIAuthenticationBreakdownSection `json:"feature_referencing"`
	EXIFCheck            *APIAuthenticationBreakdownSection `json:"exif_check"`
	PublicityCheck       *APIAuthenticationBreakdownSection `json:"publicity_check"`
	TextAnalysis         *APIAuthenticationBreakdownSection `json:"text_analysis"`
	BiometricAnalysis    *APIAuthenticationBreakdownSection `json:"biometric_analysis"`
	SecurityFeatureCheck *APIAuthenticationBreakdownSection `json:"security_feature_check"`
	RecaptureCheck       *APIAuthenticationBreakdownSection `json:"recapture_check"`
}

type APIAuthenticationBreakdownSection struct {
	Passed   bool   `json:"passed"`
	Code     uint   `json:"code,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Severity string `json:"severity,omitempty"`
}

var ZeroValue = reflect.Value{}
var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func endpointFromRegion(region, api string) string {
	switch region {
	case "us", "US", "":
		return fmt.Sprintf("https://api.idanalyzer.com/%s", api)
	case "eu", "EU":
		return fmt.Sprintf("https://api-eu.idanalyzer.com/%s", api)
	default:
		return fmt.Sprintf("%s/%s", region, api)
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func base64File(filename string) (encoded string) {
	if file, err := os.ReadFile(filename); err == nil {
		encoded = base64.StdEncoding.EncodeToString(file)
	}

	return
}

func isPrivateIP(ip net.IP) bool {
	if isPrivate := reflect.ValueOf(ip).MethodByName("IsPrivate"); isPrivate.IsValid() {
		result := isPrivate.Call([]reflect.Value{})
		return result[0].Bool()
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
