"use strict";

require('dotenv').config();
const axios = require('axios').default;

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