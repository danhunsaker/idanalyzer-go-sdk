# ID Analyzer Go SDK
This is a Go SDK for [ID Analyzer Identity Verification APIs](https://www.idanalyzer.com), though all the APIs can be called with without the SDK using simple HTTP requests as outlined in the [documentation](https://developer.idanalyzer.com), you can use this SDK to accelerate server-side development.

We strongly discourage users to connect to ID Analyzer API endpoint directly  from client-side applications that will be distributed to end user, such as mobile app, or in-browser JavaScript. Your API key could be easily compromised, and if you are storing your customer's information inside Vault they could use your API key to fetch all your user details. Therefore, the best practice is always to implement a client side connection to your server, and call our APIs from the server-side.

## Installation
```shell
go get github.com/danhunsaker/idanalyzer-go-sdk
```

## Core API
[ID Analyzer Core API](https://www.idanalyzer.com/products/id-analyzer-core-api.html) allows you to perform OCR data extraction, facial biometric verification, identity verification, age verification, document cropping, document authentication (fake ID check), AML/PEP compliance check, and paperwork automation using an ID image (JPG, PNG, PDF accepted) and user selfie photo or video. Core API has great global coverage, supporting over 98% of the passports, driver licenses and identification cards currently being circulated around the world.

![Sample ID](https://www.idanalyzer.com/img/sampleid1.jpg)

The sample code below will extract data from this sample Driver License issued in California, compare it with a [photo of Lena](https://upload.wikimedia.org/wikipedia/en/7/7d/Lenna_%28test_image%29.png), and check whether the ID is real or fake.

```go
import (
    "fmt"

    "github.com/danhunsaker/idanalyzer-go-sdk"
) 

// Initialize Core API US Region with your credentials  
coreapi := idanalyzer.NewCoreAPI("Your API Key", "US");  

// Enable authentication and use 'quick' module to check if ID is authentic
coreapi.EnableAuthentication(true, "quick");

// Analyze ID image by passing URL of the ID image and a face photo (you may also use a local file)
result, _ := coreapi.ScanFrontFace("https://www.idanalyzer.com/img/sampleid1.jpg", "https://upload.wikimedia.org/wikipedia/en/7/7d/Lenna_%28test_image%29.png")

// All information about this ID will be returned in a CoreResponse1Side struct
data_result := result.Result
authentication_result = result.Authentication
face_result = result.Face

// Print result
fmt.Printf("Hello your name is %s %s<br>", data_result.FirstName, data_result.LastName);

// Parse document authentication results  
if(authentication_result){  
    if authentication_result.Score > 0.5 {  
        fmt.Print("The document uploaded is authentic<br>");  
    } else if authentication_result.Score > 0.3 {  
        fmt.Print("The document uploaded looks little bit suspicious<br>");  
    } else {  
        fmt.Print("The document uploaded is fake<br>");  
    }
}

// Parse face verification results  
if(face_result != nil){
    if(face_result.Error > 0){
        // View complete error codes under API reference: https://developer.idanalyzer.com/coreapi.html
        fmt.Printf("Face verification failed! Code: %d, Reason: %s<br>", face_result.Error, face_result.ErrorMessage);
    }else{
        if(face_result.isIdentical){
            fmt.Print("Great! Your photo looks identical to the photo on document<br>");
        }else{
            fmt.Print("Oh no! Your photo looks different to the photo on document<br>");
        }
        fmt.Printf("Similarity score: %f<br>", face_result.Confidence);
    }
}
```
You could also set additional parameters before performing ID scan:  
```go
coreapi.EnableVault(true,false,false,false);  // enable vault cloud storage to store document information and image
coreapi.SetBiometricThreshold(0.6); // make face verification more strict  
coreapi.EnableAuthentication(true, `quick`); // check if document is real using 'quick' module  
coreapi.EnableBarcodeMode(false); // disable OCR and scan for AAMVA barcodes only  
coreapi.EnableImageOutput(true,true,"url"); // output cropped document and face region in URL format  
coreapi.EnableDualsideCheck(true); // check if data on front and back of ID matches  
coreapi.SetVaultData("user@example.com",12345,"AABBCC"); // store custom data into vault  
coreapi.RestrictCountry("US,CA,AU"); // accept documents from United States, Canada and Australia  
coreapi.RestrictState("CA,TX,WA"); // accept documents from california, texas and washington  
coreapi.RestrictType("DI"); // accept only driver license and identification card  
coreapi.SetOCRImageResize(0); // disable OCR resizing  
coreapi.VerifyExpiry(true); // check document expiry  
coreapi.VerifyAge("18-120"); // check if person is above 18  
coreapi.VerifyDOB("1990/01/01"); // check if person's birthday is 1990/01/01  
coreapi.VerifyDocumentNumber("X1234567"); // check if the person's ID number is X1234567  
coreapi.VerifyName("Elon Musk"); // check if the person is named Elon Musk  
coreapi.VerifyAddress("123 Sunny Rd, California"); // Check if address on ID matches with provided address  
coreapi.VerifyPostcode("90001"); // check if postcode on ID matches with provided postcode
coreapi.EnableAMLCheck(true); // enable AML/PEP compliance check
coreapi.SetAMLDatabase("global_politicians,eu_meps,eu_cors"); // limit AML check to only PEPs
coreapi.EnableAMLStrictMatch(true); // make AML matching more strict to prevent false positives
coreapi.GenerateContract("Template ID", "PDF", array("email"=>"user@example.com")); // generate a PDF document autofilled with data from user ID 
```

To **scan both front and back of ID**:

```go
result = coreapi.ScanBoth("path/to/id_front.jpg", "path/to/id_back.jpg");
```
To perform **biometric photo verification**:

```go
result = coreapi.ScanFrontFace("path/to/id.jpg", "path/to/face.jpg");
```
To perform **biometric video verification**:

```go
result = coreapi.ScanFrontVideoCustomPasscode("path/to/id.jpg", "path/to/video.mp4", "1234");
```
Check out sample response fields visit [Core API reference](https://developer.idanalyzer.com/coreapi.html##readingresponse).

## DocuPass Identity Verification API
[DocuPass](https://www.idanalyzer.com/products/docupass.html) allows you to verify your users without designing your own web page or mobile UI. A unique DocuPass URL can be generated for each of your users and your users can verify their own identity by simply opening the URL in their browser. DocuPass URLs can be directly opened using any browser,  you can also embed the URL inside an iframe on your website, or within a WebView inside your iOS/Android/Cordova mobile app.

![DocuPass Screen](https://www.idanalyzer.com/img/docupassliveflow.jpg)

DocuPass comes with 4 modules and you need to [choose an appropriate DocuPass module](https://www.idanalyzer.com/products/docupass.html) for integration.

To start, we will assume you are trying to **verify one of your user that has an ID of "5678"** in your own database, we need to **generate a DocuPass verification request for this user**. A unique **DocuPass reference code** and **URL** will be generated.

```go
import (
    "fmt"

    "github.com/danhunsaker/idanalyzer-go-sdk"
)

// Initialize DocuPass with your credential, company name and API region
docupass := idanalyzer.NewDocuPassAPI("API Key", "My Company Inc.", "US");  

// We need to set an identifier so that we know internally who we are verifying, this string will be returned in the callback. You can use your own user/customer id.  
docupass.SetCustomID("5678");  

// Enable vault cloud storage to store verification results, so we can look up the results  
docupass.EnableVault(true);  

// Set a callback URL where verification results will be sent, you can use docupass_callback in demo folder as a template  
docupass.SetCallbackURL("https://www.your-website.com/docupass_callback"); 

// We want DocuPass to return document image and user face image in URL format so we can store them on our own server later.  
docupass.SetCallbackImage(true, true, 1);  

// We will do a quick check on whether user have uploaded a fake ID  
docupass.EnableAuthentication(true, "quick", 0.3);  

// Enable photo facial biometric verification with threshold of 0.5  
docupass.EnableFaceVerification(true, 1, 0.5);  

// Users will have only 1 attempt at verification  
docupass.SetMaxAttempt(1);  

// We want to redirect user back to your website when they are done with verification  
docupass.SetRedirectionURL("https://www.your-website.com/verification_succeeded", "https://www.your-website.com/verification_failed");

// Get user to review and sign legal document (such as rental contract) prefilled with ID data
docupass.SignContract("Template ID", "PDF"); 

// Create a session using DocuPass Standard Mobile module
result, _ := docupass.CreateMobile();
  
if(result.Error != nil){  
    // Something went wrong  
    fmt.Printf("Error Code: %d<br/>Error Message: %s", result.Error.Code, result.Error.Message);  
}else{  
    fmt.Print("Scan the QR Code below to verify your identity: <br/>");  
    fmt.Printf(`<img src="%s"><br/>`, result.QRCode);  
    fmt.Print("Or open your mobile browser and type in: ");  
    fmt.Printf(`<a href="%s">%s</a>`, result.URL, result.URL);  
}
```
If you are looking to embed DocuPass into your mobile application, simply embed `result.URL` inside a WebView. To tell if verification has been completed monitor the WebView URL and check if it matches the URLs set in `SetRedirectionURL`. (DocuPass Live Mobile currently cannot be embedded into native iOS App due to OS restrictions, you will need to open it with Safari)

Check out additional DocuPass settings:

```go
docupass.SetReusable(true); // allow DocuPass URL/QR Code to be used by multiple users  
docupass.SetLanguage("en"); // override auto language detection  
docupass.SetQRCodeFormat("000000","FFFFFF",5,1); // generate a QR code using custom colors and size  
docupass.SetWelcomeMessage("We need to verify your driver license before you make a rental booking with our company."); // Display your own greeting message  
docupass.SetLogo("https://www.your-website.com/logo.png"); // change default logo to your own  
docupass.HideBrandingLogo(true); // hide footer logo  
docupass.RestrictCountry("US,CA,AU"); // accept documents from United States, Canada and Australia  
docupass.RestrictState("CA,TX,WA"); // accept documents from california, texas and washington  
docupass.RestrictType("DI"); // accept only driver license and identification card  
docupass.VerifyExpiry(true); // check document expiry  
docupass.VerifyAge("18-120"); // check if person is above 18  
docupass.VerifyDOB("1990/01/01"); // check if person's birthday is 1990/01/01  
docupass.VerifyDocumentNumber("X1234567"); // check if the person's ID number is X1234567  
docupass.VerifyName("Elon Musk"); // check if the person is named Elon Musk  
docupass.VerifyAddress("123 Sunny Rd, California"); // Check if address on ID matches with provided address  
docupass.VerifyPostcode("90001"); // check if postcode on ID matches with provided postcode
docupass.SetCustomHTML("https://www.yourwebsite.com/docupass_template.html"); // use your own HTML/CSS for DocuPass page
docupass.SmsVerificationLink("+1333444555"); // Send verification link to user's mobile phone
docupass.EnablePhoneVerification(true); // get user to input their own phone number for verification
docupass.VerifyPhone("+1333444555"); // verify user's phone number you already have in your database
docupass.EnableAMLCheck(true); // enable AML/PEP compliance check
docupass.SetAMLDatabase("global_politicians,eu_meps,eu_cors"); // limit AML check to only PEPs
docupass.EnableAMLStrictMatch(true); // make AML matching more strict to prevent false positives
docupass.GenerateContract("Template ID", "PDF", array("somevariable"=>"somevalue")); // automate paperwork by generating a document autofilled with ID data 
docupass.SignContract("Template ID", "PDF", array("somevariable"=>"somevalue")); // get user to sign a document as part of the identity verification process
```

Now we need to write a **callback script** or if you prefer to call it a **webhook**, to receive the verification results. This script will be called as soon as user finishes identity verification. In this guide, we will name it **docupass_callback**:

```go
import (
    "fmt"

    "github.com/danhunsaker/idanalyzer-go-sdk"
)

// Get raw post body  
input_raw := io.ReadAll(os.StdIn)  

// Parse JSON into DocuPassIdentityCallback
var data idanalyzer.DocuPassIdentityCallback
json.Unmarshal(input_raw, &data);  

// Check if we've gotten required data for validation against DocuPass server, we do this to prevent someone spoofing a callback  
if(data.Reference == "" || data.Hash == "") exit();  

// Initialize DocuPass with your credentials and company name  
docupass := idanalyzer.NewDocuPassAPI("Your API Key", "My Company Inc.", "US");  

// Validate result with DocuPass API Server  
validation, _ := docupass.Validate(data.Reference, data.Hash);  

if(validation){  
    userID := data.CustomID; // This value should be "5678" matching the User ID in your database
    
    if(data.Success){  
        // User has completed identity verification successfully

        // Get some information about your user
        firstName := data.Data.FirstName;
        lastName := data.Data.LastName;
        dob := data.Data.DOB;

        // Additional steps to store identity data into your own database
        
    }else{  
        // User did not pass identity verification  
        fail_code := data.FailCode;
        fail_reason := data.FailReason;
            
        // Save failed reason so we can investigate further  
        fmt.Fprintf("failed_verifications.txt", "userID has failed identity verification, DocuPass Reference: %s, Fail Reason: %s Fail Code: %d\n", data.Reference, fail_reason, fail_code);  
        
        // Additional steps to store why identity verification failed into your own database
        
        }  
}else{
    exit("Failed to validate DocuPass results against DocuPass server");
}
```

Visit [DocuPass Callback reference](https://developer.idanalyzer.com/docupass_callback.html) to check out the full payload returned by DocuPass.

For the final step, you could create two web pages (URLS set via `SetRedirectionURL`) that display the results to your user. DocuPass reference will be passed as a GET parameter when users are redirected, for example: https://www.your-website.com/verification_succeeded?reference=XXXXXXXXX, you could use the reference code to fetch the results from your database. P.S. We will always send callbacks to your server before redirecting your user to the set URL.

## DocuPass Signature API

You can get user to review and remotely sign legal document in DocuPass without identity verification, to do so you need to create a DocuPass Signature session.

```go
docupass := idanalyzer.NewDocuPassAPI(apikey, "My Company Inc.", api_region);

// We need to set an identifier so that we know internally who is signing the document, this string will be returned in the callback. You can use your own user/customer id.
docupass.SetCustomID(emailAddress);

// Enable vault cloud storage to store signed document
docupass.EnableVault(true);

// Set a callback URL where signed document will be sent, you can use docupass_callback under this folder as a template to receive the result
docupass.SetCallbackURL("https://www.your-website.com/docupass_callback");

// We want to redirect user back to your website when they are done with document signing, there will be no fail URL unlike identity verification
docupass.SetRedirectionURL("https://www.your-website.com/document_signed.html", "");

/*
 * more settings
docupass.SetReusable(true); // allow DocuPass URL/QR Code to be used by multiple users
docupass.SetLanguage("en"); // override auto language detection
docupass.SetQRCodeFormat("000000","FFFFFF",5,1); // generate a QR code using custom colors and size
docupass.HideBrandingLogo(true); // hide default branding footer
docupass.SetCustomHTML("https://www.yourwebsite.com/docupass_template.html"); // use your own HTML/CSS for DocuPass page
docupass.SMSContractLink("+1333444555"); // Send signing link to user's mobile phone
*/

// Assuming in your contract template you have a dynamic field %{email} and you want to fill it with user email
prefill = map[string]interface{}{
  "email": emailAddress,
};

// Create a signature session
result = docupass.CreateSignature("Template ID", "PDF", prefill);

if (result.Error != nil) {
    // Something went wrong
    exit(fmt.Sprintf("Error Code: %d<br/>Error Message: %s", result.Error.Code, result.Error.Message);
} else {
    // Redirect browser to DocuPass URL, the URL will work on both Desktop and Mobile
    SetHeader(fmt.Sprintf("Location: %s", result.URL));
    exit();
}
```

Once user has reviewed and signed the document, the signed document will be sent back to your server using callback under the `Contract.DocumentURL` field, the contract will also be saved to vault if you have enabled vault.

## Vault API

ID Analyzer provides free cloud database storage (Vault) for you to store data obtained through Core API and DocuPass. You can set whether you want to store your user data into Vault through `EnableVault` while making an API request with Go SDK. Data stored in Vault can be looked up through [Web Portal](https://portal.idanalyzer.com) or via Vault API.

If you have enabled Vault, Core API and DocuPass will both return a vault entry identifier string called `VaultID`,  you can use the identifier to look up your user data:

```go
import (
    "github.com/danhunsaker/idanalyzer-go-sdk"
)

// Initialize Vault API with your credentials  
vault := idanalyzer.NewVaultAPI("API Key", "US");  
  
// Get the vault entry using Vault Entry Identifier received from Core API/DocuPass 
vaultdata := vault.Get("VAULT_ID");
```
You can also list the items in your vault, the following example list 5 items created on or after 2021/02/25, sorted by first name in ascending order, starting from first item:

```go
vaultItems := vault.List([]string{"createtime>=2021/02/25"}, "firstName","ASC", 5, 0);
```

Alternatively, you may have a DocuPass reference code which you want to search through vault to check whether user has completed identity verification:

```go
vaultItems := vault.List([]string{"docupass_reference=XXXXXXXXXXXXX"}, "", "", 0, 0);
```
Learn more about [Vault API](https://developer.idanalyzer.com/vaultapi.html).

## AML API

ID Analyzer provides Anti-Money Laundering AML database consolidated from worldwide authorities,  AML API allows our subscribers to lookup the database using either a name or document number. It allows you to instantly check if a person or company is listed under **any kind of sanction, criminal record or is a politically exposed person(PEP)**, as part of your **AML compliance KYC**. You may also use automated check built within Core API and DocuPass.

```go
import (
    "github.com/danhunsaker/idanalyzer-go-sdk"
)

// Initialize AML API with your credentials
aml := idanalyzer.NewAMLAPI(apikey, api_region);

// Set AML database to only search the PEP category
aml.SetAMLDatabase("global_politicians,eu_cors,eu_meps");

// Search for a politician
result, _ := aml.SearchByName("Joe Biden");
fmt.Printf("%v", result);

// Set AML database to all databases
aml.SetAMLDatabase("");

// Search for a sanctioned ID number
result, _ = aml.SearchByIDNumber("AALH750218HBCLPC02");
fmt.Printf("%v", result);
```

Learn more about [AML API](https://developer.idanalyzer.com/amlapi.html).

## Error Catching

The API server may return error responses such as when document cannot be recognized. You can either manually inspect the response returned by API, or you may check the `error` return value as normally expected in Go applications. (The examples above have uniformly discarded them.)

## Demo
Check out **/demo** folder for more Go demo codes.

## SDK Reference
Check out [ID Analyzer Go SDK Reference](https://idanalyzer.github.io/id-analyzer-go-sdk/)
