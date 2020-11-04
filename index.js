"use strict";

require('dotenv').config();
const axios = require('axios').default;

function generateCertificate() {
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
		let validHostname = /^(\*\.)?([\w\d]+\.?)*\.\w+$/i;
		input.forEach((hostname) => {
			if (!validHostname.test(hostname)) {
				throw new Error(`Hostname "${hostname}" is not a valid hostname`);
			}
		});

		const domainRegex = /[\w\d]+(?=\.\w+)/gi;
		const longestHostname = input.reduce(function (a, b) { return a.length > b.length ? a : b; });
		console.log('longest hostname ', longestHostname);
		console.log('longest hostname regex ', longestHostname.match(domainRegex));
		fileName = "cloudflare-" + longestHostname.match(domainRegex).join("-");

		return input;
	} catch (e) {
		throw new Error("Hostname is not in valid JSON array format");
	}
}

function checkValidityLength() {
	const valid = [7, 30, 90, 365, 730, 1095, 5475];
	const input = parseInt(process.env.CLOUDFLARE_VALIDITY);
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

const spawn = require('child_process').spawn;

function createEcdsaPrivKey() {
	let openssl = spawn("openssl", ['ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', fileName + '.key'], {
		cwd: '/tmp/',
		windowsHide: true
	});
	openssl.stdout.setEncoding('utf8');
	openssl.stdout.on('data', (data) => {
		console.log(data);
	});
	openssl.stderr.on('data', (data) => {
		console.error(data);
	});
	openssl.on('error', (err) => {
		console.error(err);
	});
	openssl.on('close', (code, signal) => {
		console.log('Openssl closed with code ' + code);
		finishedKey();
	});
	openssl.on('exit', (code, signal) => {
		console.log('Openssl exited with code ' + code);
		finishedKey();
	});

	function finishedKey() {
		console.info("ready");
	}
}

generateCertificate();