## Synopsis

An API to scan website certificates, among other things. Also, the front-end of a web application to display the output of the API calls more graphically for the user.

## API Calls

* Chain
* DNS
* Download
* Scan

## DNS

A call to this function will parse a URL for the host, path, and port and resolve all IPv4 addresses mapping to the host.

**Method**: POST  
**Route**:  https://[you_domain_name]/api/dns  
**Input-Type**: JSON  
**Output-Type**: JSON  

#### Parameters ####

Name | Description | Default
------------ | ------------- | -------------
url | The URL to be resolved | null

#### Result ####

Name | Description
------------ | -------------
host | The parsed host from the request URL
addresses | A list of the resolved addresses
path | The parsed path from the URL
port | The parsed port from the URL

## Scan

A call to this function will scan the certificate chain and other cecurity information of the requested website.

**Method**: POST  
**Route**:  https://[you_domain_name]/api/scan  
**Input-Type**: JSON  
**Output-Type**: JSON  

#### Parameters ####

Name | Description | Default
------------ | ------------- | -------------
url | The host to be scanned. **This is the only required field**. | null
ip | The host IP address of the site to be scanned. This is optional parameter used when you wish to scan a specific IP address of a website. | null
path | The path to be scanned. | "/"
port | The port to be scanned. | 443
live_scan | Whether or not to perform a scan directly instead of checking for cached records. | "false"
advanced | Whether or not to add configuration properties to the report. | "false"

#### Result ####

The result is contained with a "reponse" field.

Name | Description | Included in intermediate and root certificates
------------ | ------------- | -------------
id | The ID of the certificate in the database | Yes
subject | Subjectal information for the certificate | Yes
issuer | Subjectal information for the certificate's issuer | Yes
cert_type | Classification of certificate (DV, OV, EV) | No
valid_from | Certificate validity period | Yes
valid_to | Certificate validity period | Yes
serialNumber | Certificate serial number | Yes
raw | X509 certificate in string format | Yes
self_signed | Whether the CA is trusted or not | No
chain_of_trust_complete | Whether the certificate's chain is complete & trusted | No
revoked | Whether the certificate has been revoked | No
next_cert_id | If the next certificate in the chain is missing, and the missing certificate is stored in our database, this field gives the ID of the certificate in our database so it can be downloaded | Yes
ip_address | The IP address which was scanned to get the report | No
server | The server's signature | No
scan_duration | The time, in seconds, to complete the scan | No
scan_time | The time the scan was completed | Yes
insecure_links | A list of insecure links found in the server's response | No
ciphersuites | A list of the server's supported ciphersuites and their ranking | No
san_entries | A list of the certificates SAN entrues | No
dump | The output of the "certutil -dump" command on the certificate | Yes
issuerCertificate | A reference to the object of the issuer certificate (if available). The certificate object contains all the fields in this table with a "Yes" in the third column. | Yes

## Chain

A call to this function with a certificate ID will send back a certificate chain in the form of a .crt file.

**Method**: GET  
**Route**:  https://[you_domain_name]/api/dns?id=request_id 
**Output-Type**: .crt file  

#### Parameters ####

Name | Description | Default
------------ | ------------- | -------------
id | The ID of the certifcate who's chain is being requested | null


## Download

A call to this function with a certificate ID will send back a file of the raw certificate in the requested format (.crt or .der).

**Method**: GET  
**Route**:  https://[you_domain_name]/api/dns?id=request_id&type=crt  
**Output-Type**: .crt file  

#### Parameters ####

Name | Description | Default
------------ | ------------- | -------------
id | The ID of the certifcate who's chain is being requested | null
type | The format the certificate will be written in. Options are crt & der. Anything other than der will default to crt. | crt

