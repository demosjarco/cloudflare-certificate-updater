"use strict";

require('dotenv').config();
const axios = require('axios').default;
const spawn = require('child_process').spawn;
const fs = require('fs');

function chown(path, user, group = user) {
	const uidNumber = require('uid-number');
	
	uidNumber(user, group, function (er, uid, gid) {
		if (er) throw er;
		
		fs.chown(path, uid, gid, (err) => {
			if (err) throw err;
		});
	});
}

function generateCertificate() {
	checkHostnames();

	switch (checkKeyType()) {
		case "origin-ecc":
			createEcdsaPrivKey();
			break;
	}
}

let fileName = "cloudflare-";

function checkHostnames() {
	try {
		let input = JSON.parse(process.env.CLOUDFLARE_HOSTNAMES);
		let validHostname = /^(\*\.)?([\w\-]+\.?)*\.\w+$/i;
		input.forEach((hostname) => {
			if (!validHostname.test(hostname)) {
				throw new Error(`Hostname "${hostname}" is not a valid hostname`);
			}
		});

		const domainRegex = /[\w\d]+(?=\.\w+)/gi;
		const longestHostname = input.reduce(function (a, b) { return a.length > b.length ? a : b; });
		fileName = "cloudflare-" + longestHostname.match(domainRegex).join("-");

		return input;
	} catch (e) {
		throw new Error("Hostname is not in valid JSON array format");
	}
}

function checkValidityLength() {
	const valid = [7, 30, 90, 365, 730, 1095, 5475];
	const input = parseInt(process.env.CLOUDFLARE_VALIDITY) || 5475;
	if (valid.includes(input)) {
		if (input > 398) {
			console.warn("Mozilla, Google, and Apple browsers will not trust this certificate by default since it's validity is longer than 398 days. See https://ccadb-public.secure.force.com/mozillacommunications/CACommResponsesOnlyReport?CommunicationId=a051J000042AUSv&QuestionId=Q00105,Q00106,Q00107");
		}
		return input;
	} else {
		throw new Error("Invalid validity length. Valid choices: 7, 30, 90, 365, 730, 1095, 5475")
	}
}

function checkKeyType() {
	//const valid = ["origin-rsa", "origin-ecc"];
	const valid = ["origin-ecc"];
	const input = process.env.CLOUDFLARE_CERT_TYPE;
	if (valid.includes(input)) {
		return input;
	} else {
		throw new Error("Invalid key type. Valid choices: origin-rsa, origin-ecc");
	}
}

function createEcdsaPrivKey() {
	let openssl = spawn("openssl", [
		'ecparam',
		'-name secp384r1',
		'-genkey',
		'-noout',
		'-out ' + fileName + '.key'
	], {
		cwd: '/etc/ssl/private/',
		shell: true,
		windowsHide: true
	});
	openssl.stdout.setEncoding('utf8');
	openssl.stdout.on('data', (data) => {
		console.log(data);
	});
	openssl.stderr.setEncoding('utf8');
	openssl.stderr.on('data', (data) => {
		console.error(data);
	});
	openssl.on('error', (err) => {
		console.error(err);
	});
	openssl.on('close', (code, signal) => {		
		if (code === 0) {
			fs.chmod('/etc/ssl/private/' + fileName + '.key', fs.constants.S_IRUSR | fs.constants.S_IWUSR | fs.constants.S_IRGRP, (error) => {
				if (error) throw error;
			});

			chown('/etc/ssl/private/' + fileName + '.key', 'root', 'ssl-cert');

			createEcdsaCsr('/etc/ssl/private/' + fileName + '.key');

			console.log('Private key file location:', '/etc/ssl/private/' + fileName + '.key');
		}
	});
}

function createEcdsaCsr(path) {
	function validateCountry() {
		const countries = require("i18n-iso-countries");
		let input = process.env.CLOUDFLARE_CERT_C;
		const alpha3regex = /^\w{3}$/i;
		const numericRegex = /\d{3}/i;

		if (alpha3regex.test(input)) {
			input = countries.alpha3ToAlpha2(input);
		} else if (numericRegex.test(input)) {
			input = countries.numericToAlpha2(input);
		}
		
		if (countries.isValid(input)) {
			return input;
		} else {
			throw new Error(input + "is an invalid country code");
		}
	}

	function validateState() {
		const stateRegex = /[\w\s]+/i;
		const input = process.env.CLOUDFLARE_CERT_ST;

		if (stateRegex.test(input)) {
			return input;
		} else {
			throw new Error(input + "is an invalid state");
		}
	}
	
	function validateLocation() {
		const stateRegex = /[\w\s]+/i;
		const input = process.env.CLOUDFLARE_CERT_L;

		if (stateRegex.test(input)) {
			return input;
		} else {
			throw new Error(input + "is an invalid location");
		}
	}

	function validateOrganization() {
		const orgRegex = /[\w\s]+/i;
		const input = process.env.CLOUDFLARE_CERT_O;

		if (orgRegex.test(input)) {
			return input;
		} else {
			throw new Error(input + "is an invalid organization");
		}
	}

	function validateCommonName() {
		const cnRegex = /([\w\-]+\.?)+\.\w+$/i;
		const input = process.env.CLOUDFLARE_CERT_CN;

		if (cnRegex.test(input)) {
			return input;
		} else {
			throw new Error(input + "is an invalid common name/fqdn");
		}
	}

	let openssl = spawn("openssl", [
		'req',
		'-new',
		'-sha512',
		'-key ' + path,
		'-out ' + fileName + '.csr',
		'-subj "/C=' + validateCountry() + '/ST=' + validateState() + '/L=' + validateLocation().replace(/(\s+)/g, '\\$1') + '/O=' + validateOrganization().replace(/(\s+)/g, '\\$1') + '/CN=' + validateCommonName() + '"'
	], {
		cwd: '/tmp/',
		shell: true,
		windowsHide: true
	});
	openssl.stdout.setEncoding('utf8');
	openssl.stdout.on('data', (data) => {
		console.log(data);
	});
	openssl.stderr.setEncoding('utf8');
	openssl.stderr.on('data', (data) => {
		console.error(data);
	});
	openssl.on('error', (err) => {
		console.error(err);
	});
	openssl.on('close', (code, signal) => {
		if (code === 0) {
			fs.chmod('/tmp/' + fileName + '.csr', fs.constants.S_IRUSR | fs.constants.S_IWUSR | fs.constants.S_IRGRP, (error) => {
				if (error) throw error;
			});

			chown('/tmp/' + fileName + '.csr', 'root', 'ssl-cert');

			uploadCsr('/tmp/' + fileName + '.csr');
		}
	});
}

function uploadCsr(path) {
	fs.readFile(path, 'utf8', (err, data) => {
		if (err) throw err;

		axios.post('https://api.cloudflare.com/client/v4/certificates', JSON.stringify({
			"hostnames": checkHostnames(),
			"requested_validity": checkValidityLength(),
			"request_type": checkKeyType(),
			"csr": data
		}), {
			headers: {
				'Content-Type': 'application/json',
				'X-Auth-User-Service-Key': process.env.CLOUDFLARE_ORIGIN_CA_KEY
			}
		}).catch((error) => {
			console.error(error.response.data);
			throw error;
		}).then((response) => {
			if (response.data.success) {
				fs.unlink(path, (err2) => {
					if (err2) throw err2;
				});

				createCertificate(response.data.result.certificate);
				console.log('Got an', response.data.result.request_type, 'certificate from Cloudflare for', response.data.result.hostnames, 'that expires on', new Date(response.data.result.expires_on).toString());
			} else {
				response.data.errors.forEach((cfError) => {
					console.error(cfError);
				});
			}
		});
	});
}

function createCertificate(certificate) {
	fs.writeFile('/etc/ssl/certs/' + fileName + '.crt', certificate, (err) => {
		if (err) throw err;

		fs.chmod('/etc/ssl/certs/' + fileName + '.crt', fs.constants.S_IRUSR | fs.constants.S_IWUSR | fs.constants.S_IRGRP | fs.constants.S_IROTH, (error) => {
			if (error) throw error;
		});

		chown('/etc/ssl/certs/' + fileName + '.crt', 'root', 'ssl-cert');

		console.log('Public certificate file location:', '/etc/ssl/certs/' + fileName + '.crt');
	});

	let finalCert = certificate;
	let rootCertUrl = '';
	switch (checkKeyType()) {
		case "origin-ecc":
			rootCertUrl = 'https://support.cloudflare.com/hc/article_attachments/360037898732/origin_ca_ecc_root.pem';
			break;
	}

	axios.get(rootCertUrl).catch((error) => {
		throw error;
	}).then((response) => {
		finalCert += response.data;

		fs.writeFile('/etc/ssl/certs/' + fileName + '-bundle.crt', finalCert, (err) => {
			if (err) throw err;

			fs.chmod('/etc/ssl/certs/' + fileName + '-bundle.crt', fs.constants.S_IRUSR | fs.constants.S_IWUSR | fs.constants.S_IRGRP | fs.constants.S_IROTH, (error) => {
				if (error) throw error;
			});

			chown('/etc/ssl/certs/' + fileName + '-bundle.crt', 'root', 'ssl-cert');

			console.log('Public bundle certificate file location:', '/etc/ssl/certs/' + fileName + '-bundle.crt');
		});
	});
}

generateCertificate();