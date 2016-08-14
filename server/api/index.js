import { Router } from 'express';
import { getDomains, getCertificate, parseCertificate, randCertFileName, execute } from '../lib/util.js';
import query from '../lib/db.js';
import fs from 'fs';
import child_process from 'child_process';
var crypto = require('crypto');
const exec = child_process.exec;

export default function() {
    // Initialize our router
    let router = Router();

    // Middleware to use for all requests
    router.use(function(req, res, next) {
        // Do logging
        console.log('Something is happening.');
        next();
    });

    

    // Test route to make sure everything is working (accessed at GET http://localhost:8080/api)
    router.get('/', function(req, res) {
        res.json({ message: 'welcome to our api!' });
    });

    // on routes that end in /download
    // ----------------------------------------------------
    router.route('/download')

    // serve certificate in file format specified
    .get(function(req, res) {
        // Check if the ID is specified
        if (req.query.id == undefined) {
            res.end();
            return;
        }
        // Search for certificate
        query(`SELECT body, cn, o FROM certificates WHERE cert_id = ${req.query.id}`, (err, result) => {
            // If not found, exit
            if (err || result.rows.length == 0) {
                res.end();
                return;
            }
            let name = (result.rows[0].cn == 'undefined') ? result.rows[0].o : result.rows[0].cn;
            name = name.replace('*.', '');
            let file = `${name}.crt`;
            let body = result.rows[0].body;
            // Write certificate to PEM file temporarily
            fs.writeFile(file, body, function(err) {
                if (err) {
                    console.error("Error writing certificate: " + err);
                    res.end();
                    return;
                }
                // If the client requested it in DER format
                if (req.query.type == 'der') {
                    let der_file = `${name}.der`;
                    // Run certutil to convert it
                    execute(`certutil -decode "${file}" "${der_file}"`, function(out) {
                        // Delete the PEM file
                        fs.unlink(file);
                        // Let the user download the DER cert
                        res.download(der_file, der_file, (err) => {
                            if (err) console.log(err);
                            // Delete the file when complete
                            fs.unlink(der_file);
                        });
                    });
                } else {
                    // Let the user download the PEM cert
                    res.download(file, file, (err) => {
                        if (err) console.log(err);
                        // Delete the file when complete
                        fs.unlink(file);
                    });
                }
            });
        });
    });

    // on routes that end in /chain
    // ----------------------------------------------------
    router.route('/chain')

    // serve certificate in file format specified
    .get(function(req, res) {
        // Check if the ID is specified
        if (req.query.id == undefined) {
            res.end();
            return;
        }

        function build_certificate_chain(cert, callback) {
            // Populate certificate fields
            let chain = {
                raw: cert.body
            };

            // If the cert has an issuer ID:
            //      1) Get it from the database
            //      2) Recursively call this function to format the database output to JSON and get the rest of the chain
            //      3) Set the result to be the current cert's issuer certificate
            //      4) Pass the updated chain to the callback function
            if (cert.issuer_cert_id) {
                // Get certificate
                query(`SELECT issuer_cert_id, body FROM certificates WHERE cert_id=${cert.issuer_cert_id}`, function(err, result) { // Step 1
                    if (err || result.rows.length == 0) {
                        callback(null);
                    } else {
                        build_certificate_chain(result.rows[0], (issuer_cert_chain) => { // Step 2
                            chain.issuerCertificate = issuer_cert_chain; // Step 3
                            callback(chain); // Step 4
                        });
                    }
                });
                // If there is no issuer ID, we can pass the current (root) cert to the callback function
            } else {
                callback(chain);
            }
        }

        // Search for certificate
        query(`SELECT body, cn, o, issuer_cert_id FROM certificates WHERE cert_id = ${req.query.id}`, (err, result) => {
            // If not found, exit
            if (err || result.rows.length == 0) {
                res.end();
                return;
            }

            build_certificate_chain(result.rows[0], (chain) => {
                let name = (result.rows[0].cn == 'undefined') ? result.rows[0].o : result.rows[0].cn;
                name = name.replace('*.', '');
                let file = `${name}.crt`;
                let c = chain;
                let body = c.raw;
                while (c.issuerCertificate) {
                    c = c.issuerCertificate;
                    body += '\n' + c.raw;
                }
                // Write certificate to PEM file temporarily
                fs.writeFile(file, body, function(err) {
                    if (err) {
                        console.error("Error writing certificate: " + err);
                        res.end();
                        return;
                    }
                    // If the client requested it in DER format
                    if (req.query.type == 'der') {
                        let der_file = `${name}.der`;
                        // Run certutil to convert it
                        execute(`certutil -decode "${file}" "${der_file}"`, function(out) {
                            // Delete the PEM file
                            fs.unlink(file);
                            // Let the user download the DER cert
                            res.download(der_file, der_file, (err) => {
                                if (err) console.log(err);
                                // Delete the file when complete
                                fs.unlink(der_file);
                            });
                        });
                    } else {
                        // Let the user download the PEM cert
                        res.download(file, file, (err) => {
                            if (err) console.log(err);
                            // Delete the file when complete
                            fs.unlink(file);
                        });
                    }
                });
            });
        });
    });

    // on routes that end in /dns
    // ----------------------------------------------------
    router.route('/dns')

    // scan a URL
    .post(function(req, res) {
        let url = req.body.url || req.certificate_lookup; // set the url name (comes from the request)
        console.log("URL: " + url);
        getDomains(url, function(result) {
            res.json(result);
        });
    });

    // on routes that end in /scan
    // ----------------------------------------------------
    router.route('/scan')

    // scan a URL
    .post(function(req, res) {
        // Get request parameters, or set default valued where applicable
        let url = req.body.url;
        let ip = req.body.ip;
        let path = req.body.path || "/";
        let port = req.body.port || "443";
        let live_scan = req.body.live_scan || "false";
        let advanced = req.body.advanced || "false";

        if (isNaN(port)) {
            port = 443;
        } else {
            port = parseInt(port);
            if (port < 0 || port > 65535) {
                port = 443;
            }
        }

        // If we don't have a URL, we can't scan
        if (!(url)) {
            console.log(req.body);
            return_report({});
            return;
        }

        let ip_query = `certificates.ip_address = '${ip}'` // Standard IP query
            // If we don't have a requested IP, we'll just take any record with a matching domain (no matter what IP)
        if (!(ip)) {
            ip_query = 'true';
        }

        // Search database for url
        console.log("Searching for " + url);
        query(`SELECT * FROM certificates, domains WHERE certificates.cert_id = domains.cert_id AND '${url}' LIKE domains.domain AND ${ip_query}`, function(err, result) {
            // If error or no result
            if (err || result.rows.length == 0) {
                // Perform new scan
                console.log("Certificate not found");
                perform_scan();
                // If found
            } else {
                console.log("Certificate found: " + result.rows[0].domain);
                // If live scan, perform scan and pass ID of certificate to be updated
                if (live_scan == "true") {
                    console.log("Live scan");
                    perform_scan(result.rows[0].cert_id);
                    // Else, build report using retrieved record
                } else {
                    build_report(result.rows[0], (report) => {
                        return_report(report);
                    });
                }
            }
        });

        /**
         * Performs the live scan, saves the results to the database and returns the report to the client
         * @param cert_id: optional cert_id to be passed if the domain we are scanning already exists in the database
         */
        function perform_scan(cert_id) {
            console.log("Performing Scan");
            // Call function to get certificate & cipher information
            getCertificate(url, ip, path, port, (cert) => {
                // Call function to parse this information
                parseCertificate(cert, (report) => {
                    // If the result is an empty object, there was an error and we are done
                    if (Object.keys(report).length == 0) {
                        return_report(report);
                        return;
                    }

                    // If the chain is incomplete, check to see if we have the next certificate in the chain stored in the DB
                    if (cert.chain_of_trust_complete || cert.self_signed) {
                        database_operations(); // If the report doesn't have the certificate chain or has a trusted chain, continue...
                    } else {
                        let last_cert = report;
                        while (last_cert.issuerCertificate) last_cert = last_cert.issuerCertificate; // Get the last cert in the chain
                        // Attempt to find issuer cert of last cert in the DB
                        query(`SELECT cert_id FROM certificates WHERE cn='${last_cert.issuer.CN}' AND ou='${last_cert.issuer.OU}' AND o='${last_cert.issuer.O}' AND city='${last_cert.issuer.L}' AND state='${last_cert.issuer.ST}' AND country='${last_cert.issuer.C}'`, function(err, result) {
                            if (!(err || result.rows.length == 0)) {
                                console.log("Found next cert in chain.");
                                last_cert.next_cert_id = result.rows[0].cert_id;
                                last_cert.chain_of_trust_complete = false;
                            } else {
                                console.log("Could not find next cert in chain.");
                            }
                            database_operations();
                        });
                    }

                    function database_operations() {
                        // Here, we perform the database operations
                        // We need to update information in a maximum of three tables: certificates, ciphersuites & domains
                        // Once we have updated the certificates table, we can sent the report to the client.
                        //      This is because we need each certificate's ID in the DB for the client to reference to download the raw cert.

                        // If a certificate ID is passed, we perform an insert, and compare the returned certificate ID with the one we already have
                        if (cert_id) {
                            insert_cert(report, (id) => {
                                return_report(report); // Certificates have been stored, return result to client
                                // Make sure an ID was passed (i.e. no error occurred)
                                if (id) {
                                    // If the IDs are different, the certificates and SAN entries related to the old ID are not useful anymore, and must be deleted
                                    if (id != cert_id) {
                                        // Delete old certificate record
                                        query(`DELETE FROM certificates WHERE cert_id = ${cert_id}`, function(err, result) {
                                            if (err) {
                                                console.error(`Error deleting certificate with ID: ${cert_id}`);
                                                console.error(err);
                                            }
                                        });
                                        // Delete the old SAN entries
                                        query(`DELETE FROM domains WHERE cert_id = ${cert_id}`, function(err, result) {
                                            if (err) {
                                                console.error(`Error deleting domains with ID: ${cert_id}`);
                                                console.error(err);
                                            }
                                        });
                                    }
                                    insert_domains(report.san_entries, id); // Add the new SAN entries
                                }
                            });
                            // If a certificate ID isn't passed, this is a new certificate so we can simply insert all the relevant data without worrying about duplication
                        } else {
                            insert_cert(report, (id) => {
                                return_report(report); // Certificates have been stored, return result to client
                                // Make sure an ID was passed (i.e. no error occurred)
                                if (id) {
                                    insert_domains(report.san_entries, id); // Add the new SAN entries
                                }
                            });
                        }
                    }
                });
            });
        }

        // Insert certificate chain into database recursively, starting with the root
        function insert_cert(cert, callback) {
            // If we have a certificate passed
            if (cert) {
                // Keep recursively calling this function, passing the issuer certificate, until we reach the root
                insert_cert(cert.issuerCertificate, (id, found_stored) => {
                    /* Once all lower level certificates are stored, this function is called
                     * id: the cert_id of the issuer certificate in the database.
                     * found_stored: boolean value representing whether or not all lower level certificates already exist in the database
                     */

                    // Specify default parameters for intermediate certs to avoid db error
                    if (cert.self_signed === undefined) {
                        cert.self_signed = false;
                        cert.chain_of_trust_complete = cert.chain_of_trust_complete || true;
                        cert.revoked = false;
                        cert.ciphersuites = [];
                        cert.insecure_links = null;
                        cert.scan_duration = null;
                    }

                    if (cert.next_cert_id == undefined) {
                        cert.next_cert_id = null;
                    }

                    let cert_issuer_id_query = (id) ? `AND issuer_cert_id=${id}` : 'AND issuer_cert_id IS NULL';

                    // Check to see if this certificate already exists in the database
                    query(`SELECT cert_id FROM certificates WHERE cn='${cert.subject.CN}' AND serial='${cert.serialNumber}' AND issuer='${cert.issuer.CN}' AND ip_address='${cert.ip_address}' ${cert_issuer_id_query}`, function(err, result) {
                        // If it doesn't, or all the lower level certificates weren't already in the database, we need to insert this cert
                        if (err || result.rows.length == 0 || !(found_stored)) {
                            let q = `INSERT INTO certificates(cn, o, ou, city, state, country, serial, issuer_cert_id, cert_type, issuer, body, valid_from_date, valid_to_date, self_signed, chain_of_trust_complete, revoked, next_cert_id, ip_address, scan_duration, server, insecure_links, scan_time_date) VALUES('${cert.subject.CN}', '${cert.subject.O}', '${cert.subject.OU}', '${cert.subject.L}', '${cert.subject.ST}', '${cert.subject.C}', '${cert.serialNumber}', ${id}, '${cert.cert_type}', '${(cert.issuer.CN || cert.issuer.O)}', '${cert.raw}', (to_timestamp('${cert.valid_from}', 'Dy, DD Mon YYYY HH24:MI:SS')), (to_timestamp('${cert.valid_to}', 'Dy, DD Mon YYYY HH24:MI:SS')), '${cert.self_signed}', '${cert.chain_of_trust_complete}', '${cert.revoked}', ${cert.next_cert_id}, '${cert.ip_address}', ${cert.scan_duration}, '${cert.server}', '${JSON.stringify(cert.insecure_links)}', (to_timestamp('${cert.scan_time}', 'Dy, DD Mon YYYY HH24:MI:SS'))) RETURNING cert_id`;
                            query(q, function(err, result) {
                                if (err) {
                                    console.error("Error inserting certificate.")
                                    console.error(err);
                                    callback(null, false);
                                } else {
                                    // Call the callback function with the newly inserted cert's id, as well as "false" to indicate we had to insert the cert, rather than it already existing
                                    cert.id = result.rows[0].cert_id;
                                    callback(result.rows[0].cert_id, false);
                                }
                            });
                            // If the certificate exists and all lower level certificates already existed in the database, we can update it and return its ID and "true" representing we didn't need to perform an insert
                        } else {
                            let cert_id = result.rows[0].cert_id;
                            cert.id = result.rows[0].cert_id;
                            query(`UPDATE certificates SET body='${cert.raw}', o='${cert.subject.O}', ou='${cert.subject.OU}', city='${cert.subject.L}', state='${cert.subject.ST}', country='${cert.subject.C}', cert_type='${cert.cert_type}', valid_from_date=(to_timestamp('${cert.valid_from}', 'Dy, DD Mon YYYY HH24:MI:SS')), valid_to_date=(to_timestamp('${cert.valid_to}', 'Dy, DD Mon YYYY HH24:MI:SS')), self_signed='${cert.self_signed}', chain_of_trust_complete='${cert.chain_of_trust_complete}', revoked='${cert.revoked}', next_cert_id=${cert.next_cert_id}, ciphersuites='${JSON.stringify(cert.ciphersuites)}', scan_duration=${cert.scan_duration}, server='${cert.server}', insecure_links='${JSON.stringify(cert.insecure_links)}', scan_time_date=(to_timestamp('${cert.scan_time}', 'Dy, DD Mon YYYY HH24:MI:SS')) WHERE cert_id=${cert_id}`, function(err, result) {
                                if (err) {
                                    console.error("Error updating certificate");
                                    console.error(err);
                                }
                                callback(cert_id, true);
                            });
                        }
                    });
                });
                // We've finally reached the root, we can start storing certificates now
            } else {
                callback(null, true);
            }
        }

        function insert_domains(san_entries, cert_id) {
            // Delete domain entries mapping to the given cert_id
            query(`DELETE FROM domains WHERE cert_id = ${cert_id}`, function(err, result) {
                if (err) {
                    console.error("Error deleting domains");
                    console.error(err);
                }
                // Create domain entries for all san fields
                for (let i = 0; i < san_entries.length; i++) {
                    query(`INSERT INTO domains(domain, cert_id) VALUES ('${san_entries[i]}', ${cert_id})`, function(err, result) {
                        if (err) {
                            console.error("Error inserting domain");
                            console.error(err);
                        }
                    });
                }
            });
        }

        function build_report(cert_domain, callback) {
            console.log("Building report from database");
            // Query for server certificate from database
            query(`SELECT * FROM certificates WHERE cert_id=${cert_domain.cert_id}`, function(err, result) {

                let cert = result.rows[0];

                // Builds certificate chain from database and returns the result for further processing
                build_certificate_chain(cert, (chain) => {

                    chain.url = cert_domain.domain;

                    // Add san_entries
                    chain.san_entries = [];
                    query(`SELECT domain FROM domains WHERE cert_id=${cert.cert_id}`, function(err, result) {
                        if (!(err)) {
                            for (let i = 0; i < result.rows.length; i++) {
                                chain.san_entries.push(result.rows[i].domain);
                            }
                        }
                        callback(chain);
                    });
                });
            });

            function build_certificate_chain(cert, callback) {
                // Populate certificate fields
                let chain = {
                    id: cert.cert_id,
                    subject: {
                        CN: (cert.cn == 'undefined') ? undefined : cert.cn,
                        O: (cert.o == 'undefined') ? undefined : cert.o,
                        OU: (cert.ou == 'undefined') ? undefined : cert.ou,
                        L: (cert.city == 'undefined') ? undefined : cert.city,
                        ST: (cert.state == 'undefined') ? undefined : cert.state,
                        C: (cert.country == 'undefined') ? undefined : cert.country
                    },
                    issuer: {
                        CN: (cert.issuer == 'undefined') ? undefined : cert.issuer
                    },
                    cert_type: cert.cert_type,
                    valid_from: (new Date(cert.valid_from_date + ' GMT')).toGMTString(),
                    valid_to: (new Date(cert.valid_to_date + ' GMT')).toGMTString(),
                    serialNumber: cert.serial,
                    raw: cert.body,
                    self_signed: cert.self_signed,
                    chain_of_trust_complete: cert.chain_of_trust_complete,
                    revoked: cert.revoked,
                    next_cert_id: cert.next_cert_id,
                    ip_address: cert.ip_address,
                    server: cert.server,
                    scan_duration: cert.scan_duration
                };

                try {
                    chain.insecure_links = JSON.parse(cert.insecure_links);
                } catch (e) {
                    chain.insecure_links = [];
                }
                // try {
                //     chain.ciphersuites = JSON.parse(cert.ciphersuites);
                // } catch (e) {
                //     chain.ciphersuites = [];
                // }
                try {
                    chain.scan_time = (new Date(cert.scan_time_date + ' GMT')).toGMTString();
                } catch (e) {
                    chain.scan_time = null;
                }

                // If the cert has an issuer ID:
                //      1) Get it from the database
                //      2) Recursively call this function to format the database output to JSON and get the rest of the chain
                //      3) Set the result to be the current cert's issuer certificate
                //      4) Pass the updated chain to the callback function
                if (cert.issuer_cert_id) {
                    // Get certificate
                    query(`SELECT * FROM certificates WHERE cert_id=${cert.issuer_cert_id}`, function(err, result) { // Step 1
                        if (err || result.rows.length == 0) {
                            callback(null);
                        } else {
                            build_certificate_chain(result.rows[0], (issuer_cert_chain) => { // Step 2
                                chain.issuerCertificate = issuer_cert_chain; // Step 3
                                callback(chain); // Step 4
                            });
                        }
                    });
                    // If there is no issuer ID, we can pass the current (root) cert to the callback function
                } else {
                    callback(chain);
                }
            }
        }

        /**
         * Function called when the report has been built, either from the database or from a live scan
         * Final touches are added to the report here, before being send back to the client
         * @param report: The compiled report
         */
        function return_report(report) {
            // Call functions to add any necessary changes to the report
            get_cert_details(report, () => {
                // Once the functions complete, send the report to the client
                try {
                    res.json({ response: report });
                    console.log("Done");
                    res.end();
                } catch (e) {
                    console.error(e);
                }
            });
        }

        /**
         * This function will use the certutil dump command to get an extended report of each certificate in the chain 
         * @param cert: the cert chain to be analyzed
         * @param callback: the function to call when complete (takes no arguments)
         */
        function get_cert_details(cert, callback) {
            // Make sure we have a report
            if (!(cert) || Object.keys(cert).length == 0 || !(cert.raw)) {
                callback(); // If the report is null, empty, or doesn't have the raw certificate call the callback function...
                return; // ...and return
            }
            let file = randCertFileName(); // Get a random filename for out cert
            fs.writeFile(file, cert.raw, function(err) { // Write the cert to a file
                if (err) {
                    console.error("Error writing certificate: " + error);
                    throw err;
                } else {
                    execute('openssl x509 -in ' + file + '  -text', function(out) { // Execute the certutil dump command
                        cert.dump = out; // Set the output of the command to an attribute in the cert
                        fs.unlink(file); // Delete the certificate file
                        get_cert_details(cert.issuerCertificate, callback); // Call this function to analyze the issuer certificate
                    });
                }
            });
        }
    });


    // on routes that end in /decoder
    // ----------------------------------------------------
    router.route('/decoder')

    // get(function(req, res) {
    //     res.send('Test');
    // });

    .post(function(req, res) {
        let body = req.body.body;
        let csr = req.body.csr;
        decode(body, csr, function(err, result) {
            if (err)
                throw err;
            res.json(result);
        });

        function decode(data, type, callback) {
            if (type == 'true') {
                let inFile = randCertFileName();
                let inFile2 = randCertFileName(); // Get a random filename for incoming cert

                var result;
                fs.writeFile(inFile, data, function(err) { // Write the cert to a file
                    if (err) {
                        console.error("Error writing certificate: " + err);
                        return callback(err);
                    }

                });
                execute('openssl req -in ' + inFile + '  -text', function(out) { // Execute the certutil dump command
                    result = out;
                    var hash = crypto.createHash('sha1').update(data).digest('hex');
                    result = result.concat('\n', 'sha1:', hash);
                    hash = crypto.createHash('md5').update(data).digest('hex');
                    result = result.concat('\n', 'md5:', hash);

                    fs.unlink(inFile); // Delete the certificate file
                    return callback(null, result);
                });
            } else if (type == 'false') {
                let inFile = randCertFileName(); // Get a random filename for incoming cert

                var result;
                fs.writeFile(inFile, data, function(err) { // Write the cert to a file
                    if (err) {
                        console.error("Error writing certificate: " + err);
                        return callback(err);
                    }
                });
                execute('openssl x509 -in ' + inFile + '  -text', function(out) { // Execute the certutil dump command
                    result = out;
                    fs.unlink(inFile); // Delete the certificate file
                    return callback(null, result);
                });
            }
        }


    });



    return router;
}
