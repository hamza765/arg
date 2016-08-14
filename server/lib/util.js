import https from 'https';
import fs from 'fs';

import dns from 'dns';
dns.setServers(["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"]);

var exec = require('child_process').exec;

/** 
 * To execute commands on the terminal
 * @param command: command to be executed
 * @param callback: callback function, which takes as input the output of the command
 */
export const execute = (command, callback) => {
    exec(command, function(error, stdout, stderr) { callback(stdout); });
};

/**
 * Random certificate filename generator
 * @returns a string beginning with 5 random digits and ending with '.crt'
 */
export const randCertFileName = () => {
    let low = 10000;
    let high = 99999;
    return `${Math.floor(Math.random() * (high - low + 1) + low)}.csr`;
};

/**
 * Given a URL, parses it to seperate the url itself (the domain), the port, and the path
 * @param url: the URL to be parsed
 * @returns an object with "url", "port" and "path" attributes
 */
const cleanURL = (url) => {

    // Remove white space
    url = url.replace(/ /g, '');

    // Remove HTTP:// or HTTPS://
    let start = 0;
    if (url.search(/HTTP:\/\//ig) == 0) start = 7;
    if (url.search(/HTTPS:\/\//ig) == 0) start = 8;
    url = url.substring(start);

    // Seperate hostname and path
    let path = "/"; // default path
    let host = url;
    let end = url.indexOf('/');
    if (end != -1) {
        path = url.substring(end);
        host = url.substring(0, end);
    }

    // Seperate hostname and port
    let port = '443'; // default port
    end = host.indexOf(':');
    if (end != -1) {
        port = host.substring(end + 1);
        host = host.substring(0, end);
    }

    // Add ".com" at the end if no other top-level domain is entered
    //if ((host.match(/\./g) || []).length < 1) host += ".com";

    return { host: host, path: path, port: port };
}

/**
 * Removes the circular reference from the root certificate in a given certificate chain 
 * @param cert: certificate chain to remove circular reference from
 */
const removeCircular = (cert) => {
    while (true) {
        if (cert == "" || cert == cert.issuerCertificate) {
            delete cert.issuerCertificate;
            break;
        }
        cert = cert.issuerCertificate || "";
    }
}

/**
 * Converts the raw certificate from byte code form to its original X509 form
 * @param cert: the certificate in byte code form
 * @returns the certificate in X509 form
 */
const toCert = (cert) => {
    cert = cert.toString('base64'); // Convert from binary to base64
    var result = "-----BEGIN CERTIFICATE-----\n";
    // After every 64 characters, add a new line
    for (var i = 0; i < cert.length; i += 64) {
        result += cert.substring(i, i + 64);
        result += '\n';
    }
    result += "-----END CERTIFICATE-----\n";
    return result;
}

/**
 * Recursively goes through the cert chain and formats relevant fields in each certificate
 * @param report: the certificate chain
 */
const formatCerts = (report) => {
    let scan_time = report.scan_time;
    while (report) {
        report.raw = toCert(report.raw);
        report.valid_from = (new Date(report.valid_from)).toGMTString();
        report.valid_to = (new Date(report.valid_to)).toGMTString();
        report.scan_time = scan_time;
        report = report.issuerCertificate;
    }
}

/**
 * Parses the result of the API call to get the ciphersuites of a particular host in JSON format
 * @param raw_ciphersuites: the string returned by the API call
 * @returns an array of the parsed ciphersuites
 */
// const parseCiphersuites = (raw_ciphersuites) => {
//     // Split by new line
//     let raw_ciphersuites_array = raw_ciphersuites.split('\n');
//     // Initialize ciphersuite array
//     let ciphersuites_array = [];
//     // Ciphersuites start on line 4
//     let i = 4,
//         currentLine = raw_ciphersuites_array[i];
//     // Continue until we reach a blank line (which is when the ciphersuites end)
//     while (currentLine != "") {
//         // Split current line by white space
//         let splitCipher = currentLine.match(/\S+/g);
//         // Create new ciphersuite object and add it to the array
//         ciphersuites_array.push({
//             priority: splitCipher[0],
//             ciphersuite: mapCipherName(splitCipher[1], splitCipher[2]),
//             protocols: splitCipher[2],
//             pfs: splitCipher[3],
//             curves: splitCipher[4]
//         });
//         currentLine = raw_ciphersuites_array[++i];
//     }
//     return ciphersuites_array;
// }

/**
 * Maps from the OpenSSL name of a ciphersuite to its specification name
 * @param cipher: The OpenSSL name
 * @param protocol: The protocol being used
 * @returns the specification name
 */
const mapCipherName = (cipher, protocol) => {
    if (protocol.indexOf('SSL') > -1) {
        let i = openSSLnames.indexOf(cipher);
        if (i != -1) {
            return specSSLnames[i];
        }
    }
    let i = openTLSnames.indexOf(cipher);
    if (i == -1) return cipher;
    else return specTLSnames[i];
}

/**
 * Parses the URL passed to it and returns a list of the resolving IP addresses
 * @param url: the url which needs to be resolved
 * @param callback: the callback function
 * @returns an object consisting of an addresses field, an port filed, and a path field.
 * The addresses field is a list of objects which each contain a url and an ip field.
 */
export let getDomains = (url, callback) => {
    url = cleanURL(url);
    let host = url.host;
    let path = url.path;
    let port = url.port;
    let addresses = [];
    // Resolve the given host to find all IP addresses
    dns.resolve4(host, (err, adds) => {
        if (err) {
            console.log("No IPv4 addresses");
        } else {
            addresses = adds;
        }
        // Pass the addresses, as well as the path and the port to the callback function
        callback({
            host: host,
            addresses: addresses,
            path: path,
            port: port
        });
    });
}

/**
 * Gets a certificate and the body of a given URL, passes the result into the given function once completed
 * On error, passes an empty object into the given function
 * @param url: the URL to be scanned
 * @param callback: the function which will process the output
 */
export let getCertificate = (url, ip, path, port, callback) => {

    /*
        In this function, we make two asynchronous calls, one to get the ciphersuites, and another to get the certificate
        We need to wait for both calls to complete and then call the callback function with the results compiled in one object (cert)
        The approach is to have a flag for each call. When one of the async calls returns, we set its flag to true, and check the flag of the other call
        If the other flag is also true, we are done and can call the callback function
    */

    let start_time = new Date();
    let cert = {}; // Final object to return
    let certificate_request = false; //flag



    // Function to call when first async call returns/times out
    // function fin() {
    //     complete();
    // }

    // Make first async call
    // let c = https.get(opts, function(r) {
    //     let str = '';

    //     //another chunk of data has been recieved, so append it to `str`
    //     r.on('data', function(d) {
    //         str += d;
    //     });

    //     //the whole response has been recieved
    //     r.on('end', function() {
    //         // console.log("Ciphersuite retrieved");
    //         // cert.ciphersuites = str;
    //         fin();
    //     });
    // });
    // // Set timeout
    // c.setTimeout(1, function() {
    //     console.log("Ciphersuite retrieval timeout");
    //     cert.ciphersuites = "";
    //     fin();
    // });
    // // Error handling  (treated the same as a timeout)
    // c.on('error', function(e) {
    //     console.log("Ciphersuite retrieval error\n" + e);
    //     cert.ciphersuites = "";
    //     fin();
    // });

    // Setting up second async call
    let options = {
        host: (ip || url),
        port: port,
        method: 'GET',
        path: path,
        rejectUnauthorized: false,
        requestOCSP: true,
        headers: {
            'Host': url
        }
    };
    options.agent = new https.Agent(options);

    // Make second call
    let req = https.request(options, function(response) {
        // Get certificate and other metadata which cannot be collected once the connection is closed
        cert = response;
        cert.url = url;
        cert.cert = response.connection.getPeerCertificate(true);
        cert.ip_address = response.connection.remoteAddress;
        cert.self_signed = false;
        cert.chain_of_trust_complete = true;
        if (!(response.connection.authorized)) {
            console.log("Unauthorized Certificate!")
            console.log(response.connection.authorizationError);
            if (response.connection.authorizationError == 'DEPTH_ZERO_SELF_SIGNED_CERT' || response.connection.authorizationError == 'SELF_SIGNED_CERT_IN_CHAIN') {
                cert.self_signed = true;
                cert.chain_of_trust_complete = false;
            } else if (response.connection.authorizationError === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
                cert.chain_of_trust_complete = false;
            }
        }

        //prepare to get website data
        cert.response_data = '';

        //collect the website data as it is received
        response.on('data', function(chunk) {
            cert.response_data += chunk;
        });

        //once all the data is collected, pass it to the given function
        response.on('end', function() {
            done();
        });
    });
    // Set timeout
    req.setTimeout(40000, function() {
        console.log("Certificate retrieval timeout");
        done();
    });
    // Error handling (treated the same as a timeout)
    req.on('error', function(e) {
        console.log("Certificate retrieval error\n" + e);
        done();
    });

    // Function to call when second async call returns/times out
    function done() {
        certificate_request = true;
        // if (ciphersuite_request) {
        complete();
        //}
    }

    // Function to call when both calls have returned/timed out
    function complete() {
        cert.scan_time = new Date();
        cert.scan_duration = (cert.scan_time.getTime() - start_time.getTime()) / 1000;
        callback(cert);
    }

    req.end();
}

/**
 * Parses certificate and ciphersuites and generates and returns a report.
 * @param response: response received from https request, with embedded certificate and cipher information
 * @param callback: the callback function which the report is passed to
 */
export let parseCertificate = (response, callback) => {

    try {
        if (!(response.cert)) {
            console.log("No certificate");
            callback({});
            return;
        }

        let data = response.response_data;

        // Initializa report object which will be returned
        let report = {};

        //Include Certificate details
        let cert = response.cert;

        // Remove circular reference in certificate chain
        try {
            removeCircular(cert);
        } catch (e) {
            console.log("Error removing circular reference:\n" + cert);
        }

        // Certificate field to copy over to report
        let certificateFields = [
            "subject",
            "raw",
            "issuer",
            "infoAccess",
            "valid_from",
            "valid_to",
            "serialNumber",
            "issuerCertificate"
        ];

        // Populate certificate fields
        for (let i = 0; i < certificateFields.length; i++) {
            report[certificateFields[i]] = cert[certificateFields[i]];
        }

        //Copy over scan time & duration
        report.scan_time = response.scan_time.toGMTString();
        report.scan_duration = response.scan_duration;

        //if this function runs, then it's a live scan
        report.live = true;

        // Recursively format specific certificate fields
        formatCerts(report);

        // Set the SAN entries
        let san;
        // Remove ", " from SAN entries, then split san entries by "DNS:"
        try {
            san = cert.subjectaltname.replace(/, /g, '').replace(/\*\./g, '%').split('DNS:');
            // Get rid of first element, which is empty
            san.shift();
        } catch (e) {
            // If there's an error (no SAN entries), set the CN as the only SAN entry.
            san = [cert.subject.CN];
        }
        report.san_entries = san;

        // Set the certificate type
        try {
            // If there is no certificate organization, the type is DV.
            report.cert_type = cert.subject.O || 'DV';
        } catch (e) {
            console.log('Error getting certificate organization');
            report.cert_type = 'DV';
        }
        if (report.cert_type != 'DV') {
            // If there was an organization, check for the keywords "EV" or "Extended Validation" in the issuer's CN
            // If we find a match, the cert type is EV, else it's OV
            try {
                if (cert.issuer.CN.search(/ EV |Extended Validation/i) == -1) {
                    report.cert_type = "OV";
                } else {
                    report.cert_type = "EV";
                }
            } catch (e) {
                console.log('Error getting issuer CN');
                report.cert_type = 'OV';
            }
        }

        // Copy over fields from the received "response" object to the final report object
        report.url = response.url;
        report.ip_address = response.ip_address;
        if (response.headers) {
            report.server = response.headers.server;
        }
        report.self_signed = response.self_signed;
        report.chain_of_trust_complete = response.chain_of_trust_complete;

        // Scan for insecure links
        try {
            
            report.insecure_links = (data.match(/src=('|")HTTP:\/\/.*?(?=('|"))|<lin.*?HTTP:\/\/.*?(?=('|"))/gi) || []);
            for (var i = 0; i < report.insecure_links.length; i++) {
                if (report.insecure_links[i].indexOf('src=') !== -1) {
                    report.insecure_links[i] = report.insecure_links[i].slice(5);
                }

                if (report.insecure_links[i].indexOf('stylesheet') !== -1) {
                    report.insecure_links[i] = report.insecure_links[i].slice(29);
                }


            }

        } catch (e) {
            console.log('Error parsing insecure links');
            report.insecure_links = [];
        }

        // Parse cipher suites
        // try {
        //     report.ciphersuites = parseCiphersuites(response.ciphersuites);
        // } catch (e) {
        //     console.log("Ciphersuite parse failed\n" + e + '\n' + response.ciphersuites);
        //     report.ciphersuites = [];
        // }

        // Get revocation status from certutil
        let file = randCertFileName();
        fs.writeFile(file, report.raw, function(err) {
            if (err) {
                // If we encounter an error writing the file, log it and send the report as is
                console.error("Error writing certificate: " + error);
                callback(report);
            } else {
                execute('certutil -f -v -verify ' + file, function(out) {
                    report.revoked = !(!(out.match(/revoked/ig))); // Check for the "revoked" keyword in the output
                    fs.unlink(file); // Delete file
                    callback(report); // Finally, return the report
                });
            }
        });
    } catch (e) {
        // If we come across an error while parsing, log it and return an empty object
        console.log("Error Parsing...\n" + e);
        callback({});
    }
}

const specSSLnames = ['SSL_RSA_WITH_NULL_MD5',
    'SSL_RSA_WITH_NULL_SHA',
    'SSL_RSA_WITH_RC4_128_MD5',
    'SSL_RSA_WITH_RC4_128_SHA',
    'SSL_RSA_WITH_IDEA_CBC_SHA',
    'SSL_RSA_WITH_3DES_EDE_CBC_SHA',
    'SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA',
    'SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA',
    'SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
    'SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
    'SSL_DH_anon_WITH_RC4_128_MD5',
    'SSL_DH_anon_WITH_3DES_EDE_CBC_SHA',
    'SSL_FORTEZZA_KEA_WITH_NULL_SHA',
    'SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA',
    'SSL_FORTEZZA_KEA_WITH_RC4_128_SHA'
];
const specTLSnames = ['TLS_RSA_WITH_NULL_MD5',
    'TLS_RSA_WITH_NULL_SHA',
    'TLS_RSA_WITH_RC4_128_MD5',
    'TLS_RSA_WITH_RC4_128_SHA',
    'TLS_RSA_WITH_IDEA_CBC_SHA',
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
    'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
    'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_DH_anon_WITH_RC4_128_MD5',
    'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
    'TLS_RSA_WITH_AES_128_CBC_SHA',
    'TLS_RSA_WITH_AES_256_CBC_SHA',
    'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
    'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
    'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
    'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
    'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
    'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_DH_anon_WITH_AES_128_CBC_SHA',
    'TLS_DH_anon_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
    'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
    'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
    'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
    'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
    'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
    'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
    'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
    'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
    'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
    'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
    'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',
    'TLS_RSA_WITH_SEED_CBC_SHA',
    'TLS_DH_DSS_WITH_SEED_CBC_SHA',
    'TLS_DH_RSA_WITH_SEED_CBC_SHA',
    'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
    'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
    'TLS_DH_anon_WITH_SEED_CBC_SHA',
    'TLS_GOSTR341094_WITH_28147_CNT_IMIT',
    'TLS_GOSTR341001_WITH_28147_CNT_IMIT',
    'TLS_GOSTR341094_WITH_NULL_GOSTR3411',
    'TLS_GOSTR341001_WITH_NULL_GOSTR3411',
    'TLS_DHE_DSS_WITH_RC4_128_SHA',
    'TLS_ECDHE_RSA_WITH_NULL_SHA',
    'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
    'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    '',
    'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
    'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
    'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    '',
    'TLS_ECDH_anon_WITH_NULL_SHA',
    'TLS_ECDH_anon_WITH_RC4_128_SHA',
    'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
    'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
    'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_NULL_SHA256',
    'TLS_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
    'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
    'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
    'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
    'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
    'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
    'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
    'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
    'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
    'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
    'RSA_WITH_AES_128_CCM',
    'RSA_WITH_AES_256_CCM',
    'DHE_RSA_WITH_AES_128_CCM',
    'DHE_RSA_WITH_AES_256_CCM',
    'RSA_WITH_AES_128_CCM_8',
    'RSA_WITH_AES_256_CCM_8',
    'DHE_RSA_WITH_AES_128_CCM_8',
    'DHE_RSA_WITH_AES_256_CCM_8',
    'ECDHE_ECDSA_WITH_AES_128_CCM',
    'ECDHE_ECDSA_WITH_AES_256_CCM',
    'ECDHE_ECDSA_WITH_AES_128_CCM_8',
    'ECDHE_ECDSA_WITH_AES_256_CCM_8',
    'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
    'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
    'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
    'PSK_WITH_NULL_SHA',
    'DHE_PSK_WITH_NULL_SHA',
    'RSA_PSK_WITH_NULL_SHA',
    'PSK_WITH_RC4_128_SHA',
    'PSK_WITH_3DES_EDE_CBC_SHA',
    'PSK_WITH_AES_128_CBC_SHA',
    'PSK_WITH_AES_256_CBC_SHA',
    'DHE_PSK_WITH_RC4_128_SHA',
    'DHE_PSK_WITH_3DES_EDE_CBC_SHA',
    'DHE_PSK_WITH_AES_128_CBC_SHA',
    'DHE_PSK_WITH_AES_256_CBC_SHA',
    'RSA_PSK_WITH_RC4_128_SHA',
    'RSA_PSK_WITH_3DES_EDE_CBC_SHA',
    'RSA_PSK_WITH_AES_128_CBC_SHA',
    'RSA_PSK_WITH_AES_256_CBC_SHA',
    'PSK_WITH_AES_128_GCM_SHA256',
    'PSK_WITH_AES_256_GCM_SHA384',
    'DHE_PSK_WITH_AES_128_GCM_SHA256',
    'DHE_PSK_WITH_AES_256_GCM_SHA384',
    'RSA_PSK_WITH_AES_128_GCM_SHA256',
    'RSA_PSK_WITH_AES_256_GCM_SHA384',
    'PSK_WITH_AES_128_CBC_SHA256',
    'PSK_WITH_AES_256_CBC_SHA384',
    'PSK_WITH_NULL_SHA256',
    'PSK_WITH_NULL_SHA384',
    'DHE_PSK_WITH_AES_128_CBC_SHA256',
    'DHE_PSK_WITH_AES_256_CBC_SHA384',
    'DHE_PSK_WITH_NULL_SHA256',
    'DHE_PSK_WITH_NULL_SHA384',
    'RSA_PSK_WITH_AES_128_CBC_SHA256',
    'RSA_PSK_WITH_AES_256_CBC_SHA384',
    'RSA_PSK_WITH_NULL_SHA256',
    'RSA_PSK_WITH_NULL_SHA384',
    'PSK_WITH_AES_128_GCM_SHA256',
    'PSK_WITH_AES_256_GCM_SHA384',
    'ECDHE_PSK_WITH_RC4_128_SHA',
    'ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
    'ECDHE_PSK_WITH_AES_128_CBC_SHA',
    'ECDHE_PSK_WITH_AES_256_CBC_SHA',
    'ECDHE_PSK_WITH_AES_128_CBC_SHA256',
    'ECDHE_PSK_WITH_AES_256_CBC_SHA384',
    'ECDHE_PSK_WITH_NULL_SHA',
    'ECDHE_PSK_WITH_NULL_SHA256',
    'ECDHE_PSK_WITH_NULL_SHA384',
    'PSK_WITH_CAMELLIA_128_CBC_SHA256',
    'PSK_WITH_CAMELLIA_256_CBC_SHA384',
    'DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
    'DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
    'RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
    'RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
    'ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
    'ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
    'PSK_WITH_AES_128_CCM',
    'PSK_WITH_AES_256_CCM',
    'DHE_PSK_WITH_AES_128_CCM',
    'DHE_PSK_WITH_AES_256_CCM',
    'PSK_WITH_AES_128_CCM_8',
    'PSK_WITH_AES_256_CCM_8',
    'DHE_PSK_WITH_AES_128_CCM_8',
    'DHE_PSK_WITH_AES_256_CCM_8',
    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256'
];
const openSSLnames = ['NULL-MD5',
    'NULL-SHA',
    'RC4-MD5',
    'RC4-SHA',
    'IDEA-CBC-SHA',
    'DES-CBC3-SHA',
    'DH-DSS-DES-CBC3-SHA',
    'DH-RSA-DES-CBC3-SHA',
    'DHE-DSS-DES-CBC3-SHA',
    'DHE-RSA-DES-CBC3-SHA',
    'ADH-RC4-MD5',
    'ADH-DES-CBC3-SHA',
    'implemented.',
    'implemented.',
    'implemented.'
];
const openTLSnames = ['NULL-MD5',
    'NULL-SHA',
    'RC4-MD5',
    'RC4-SHA',
    'IDEA-CBC-SHA',
    'DES-CBC3-SHA',
    'implemented.',
    'implemented.',
    'DHE-DSS-DES-CBC3-SHA',
    'DHE-RSA-DES-CBC3-SHA',
    'ADH-RC4-MD5',
    'ADH-DES-CBC3-SHA',
    'AES128-SHA',
    'AES256-SHA',
    'DH-DSS-AES128-SHA',
    'DH-DSS-AES256-SHA',
    'DH-RSA-AES128-SHA',
    'DH-RSA-AES256-SHA',
    'DHE-DSS-AES128-SHA',
    'DHE-DSS-AES256-SHA',
    'DHE-RSA-AES128-SHA',
    'DHE-RSA-AES256-SHA',
    'ADH-AES128-SHA',
    'ADH-AES256-SHA',
    'CAMELLIA128-SHA',
    'CAMELLIA256-SHA',
    'DH-DSS-CAMELLIA128-SHA',
    'DH-DSS-CAMELLIA256-SHA',
    'DH-RSA-CAMELLIA128-SHA',
    'DH-RSA-CAMELLIA256-SHA',
    'DHE-DSS-CAMELLIA128-SHA',
    'DHE-DSS-CAMELLIA256-SHA',
    'DHE-RSA-CAMELLIA128-SHA',
    'DHE-RSA-CAMELLIA256-SHA',
    'ADH-CAMELLIA128-SHA',
    'ADH-CAMELLIA256-SHA',
    'SEED-SHA',
    'DH-DSS-SEED-SHA',
    'DH-RSA-SEED-SHA',
    'DHE-DSS-SEED-SHA',
    'DHE-RSA-SEED-SHA',
    'ADH-SEED-SHA',
    'GOST94-GOST89-GOST89',
    'GOST2001-GOST89-GOST89',
    'GOST94-NULL-GOST94',
    'GOST2001-NULL-GOST94',
    'DHE-DSS-RC4-SHA',
    'ECDHE-RSA-NULL-SHA',
    'ECDHE-RSA-RC4-SHA',
    'ECDHE-RSA-DES-CBC3-SHA',
    'ECDHE-RSA-AES128-SHA',
    'ECDHE-RSA-AES256-SHA',
    '',
    'ECDHE-ECDSA-NULL-SHA',
    'ECDHE-ECDSA-RC4-SHA',
    'ECDHE-ECDSA-DES-CBC3-SHA',
    'ECDHE-ECDSA-AES128-SHA',
    'ECDHE-ECDSA-AES256-SHA',
    '',
    'AECDH-NULL-SHA',
    'AECDH-RC4-SHA',
    'AECDH-DES-CBC3-SHA',
    'AECDH-AES128-SHA',
    'AECDH-AES256-SHA',
    'NULL-SHA256',
    'AES128-SHA256',
    'AES256-SHA256',
    'AES128-GCM-SHA256',
    'AES256-GCM-SHA384',
    'DH-RSA-AES128-SHA256',
    'DH-RSA-AES256-SHA256',
    'DH-RSA-AES128-GCM-SHA256',
    'DH-RSA-AES256-GCM-SHA384',
    'DH-DSS-AES128-SHA256',
    'DH-DSS-AES256-SHA256',
    'DH-DSS-AES128-GCM-SHA256',
    'DH-DSS-AES256-GCM-SHA384',
    'DHE-RSA-AES128-SHA256',
    'DHE-RSA-AES256-SHA256',
    'DHE-RSA-AES128-GCM-SHA256',
    'DHE-RSA-AES256-GCM-SHA384',
    'DHE-DSS-AES128-SHA256',
    'DHE-DSS-AES256-SHA256',
    'DHE-DSS-AES128-GCM-SHA256',
    'DHE-DSS-AES256-GCM-SHA384',
    'ECDHE-RSA-AES128-SHA256',
    'ECDHE-RSA-AES256-SHA384',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-SHA256',
    'ECDHE-ECDSA-AES256-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ADH-AES128-SHA256',
    'ADH-AES256-SHA256',
    'ADH-AES128-GCM-SHA256',
    'ADH-AES256-GCM-SHA384',
    'AES128-CCM',
    'AES256-CCM',
    'DHE-RSA-AES128-CCM',
    'DHE-RSA-AES256-CCM',
    'AES128-CCM8',
    'AES256-CCM8',
    'DHE-RSA-AES128-CCM8',
    'DHE-RSA-AES256-CCM8',
    'ECDHE-ECDSA-AES128-CCM',
    'ECDHE-ECDSA-AES256-CCM',
    'ECDHE-ECDSA-AES128-CCM8',
    'ECDHE-ECDSA-AES256-CCM8',
    'ECDHE-ECDSA-CAMELLIA128-SHA256',
    'ECDHE-ECDSA-CAMELLIA256-SHA384',
    'ECDHE-RSA-CAMELLIA128-SHA256',
    'ECDHE-RSA-CAMELLIA256-SHA384',
    'PSK-NULL-SHA',
    'DHE-PSK-NULL-SHA',
    'RSA-PSK-NULL-SHA',
    'PSK-RC4-SHA',
    'PSK-3DES-EDE-CBC-SHA',
    'PSK-AES128-CBC-SHA',
    'PSK-AES256-CBC-SHA',
    'DHE-PSK-RC4-SHA',
    'DHE-PSK-3DES-EDE-CBC-SHA',
    'DHE-PSK-AES128-CBC-SHA',
    'DHE-PSK-AES256-CBC-SHA',
    'RSA-PSK-RC4-SHA',
    'RSA-PSK-3DES-EDE-CBC-SHA',
    'RSA-PSK-AES128-CBC-SHA',
    'RSA-PSK-AES256-CBC-SHA',
    'PSK-AES128-GCM-SHA256',
    'PSK-AES256-GCM-SHA384',
    'DHE-PSK-AES128-GCM-SHA256',
    'DHE-PSK-AES256-GCM-SHA384',
    'RSA-PSK-AES128-GCM-SHA256',
    'RSA-PSK-AES256-GCM-SHA384',
    'PSK-AES128-CBC-SHA256',
    'PSK-AES256-CBC-SHA384',
    'PSK-NULL-SHA256',
    'PSK-NULL-SHA384',
    'DHE-PSK-AES128-CBC-SHA256',
    'DHE-PSK-AES256-CBC-SHA384',
    'DHE-PSK-NULL-SHA256',
    'DHE-PSK-NULL-SHA384',
    'RSA-PSK-AES128-CBC-SHA256',
    'RSA-PSK-AES256-CBC-SHA384',
    'RSA-PSK-NULL-SHA256',
    'RSA-PSK-NULL-SHA384',
    'PSK-AES128-GCM-SHA256',
    'PSK-AES256-GCM-SHA384',
    'ECDHE-PSK-RC4-SHA',
    'ECDHE-PSK-3DES-EDE-CBC-SHA',
    'ECDHE-PSK-AES128-CBC-SHA',
    'ECDHE-PSK-AES256-CBC-SHA',
    'ECDHE-PSK-AES128-CBC-SHA256',
    'ECDHE-PSK-AES256-CBC-SHA384',
    'ECDHE-PSK-NULL-SHA',
    'ECDHE-PSK-NULL-SHA256',
    'ECDHE-PSK-NULL-SHA384',
    'PSK-CAMELLIA128-SHA256',
    'PSK-CAMELLIA256-SHA384',
    'DHE-PSK-CAMELLIA128-SHA256',
    'DHE-PSK-CAMELLIA256-SHA384',
    'RSA-PSK-CAMELLIA128-SHA256',
    'RSA-PSK-CAMELLIA256-SHA384',
    'ECDHE-PSK-CAMELLIA128-SHA256',
    'ECDHE-PSK-CAMELLIA256-SHA384',
    'PSK-AES128-CCM',
    'PSK-AES256-CCM',
    'DHE-PSK-AES128-CCM',
    'DHE-PSK-AES256-CCM',
    'PSK-AES128-CCM8',
    'PSK-AES256-CCM8',
    'DHE-PSK-AES128-CCM8',
    'DHE-PSK-AES256-CCM8',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'DHE-RSA-CHACHA20-POLY1305',
    'PSK-CHACHA20-POLY1305',
    'ECDHE-PSK-CHACHA20-POLY1305',
    'DHE-PSK-CHACHA20-POLY1305',
    'RSA-PSK-CHACHA20-POLY1305'
];
