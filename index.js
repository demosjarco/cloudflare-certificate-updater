"use strict";

require('dotenv').config();
const axios = require('axios').default;
const spawn = require('child_process').spawn;
const fs = require('fs');

function chown(path, user, group = user) {
	const uidNumber = require("uid-number");
	
	uidNumber(user, function (er1, uid1, gid1) {
		if (er1) console.error(er1);
		
		uidNumber(group, function (er2, uid2, gid2) {
			if (er2) console.error(er2);

			fs.chown(path, uid1, gid2, (err) => {
				if (err) throw err;

				console.log(path, 'ownership has been changed to ' + user + ' (' + uid1 + ') : ' + group + ' (' + gid2 + ')');
			});
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
		console.log('Openssl gen closed with code ' + code);
		
		if (code === 0) {
			fs.chmod('/etc/ssl/private/' + fileName + '.key', fs.constants.S_IRUSR | fs.constants.S_IWUSR | fs.constants.S_IXUSR | fs.constants.S_IXGRP, (error) => {
				if (error) throw error;
				console.log('/etc/ssl/private/' + fileName + '.key permissions has been changed to 710');
			});

			chown('/etc/ssl/private/' + fileName + '.key', 'root', 'ssl-cert');

			createEcdsaCsr();
		}
	});
}

function createEcdsaCsr() {
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
		'-key /etc/ssl/private/' + fileName + '.key',
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
		console.log('Openssl req closed with code ' + code);

		if (code === 0) {
			fs.chmod('/tmp/' + fileName + '.csr', fs.constants.S_IRUSR | fs.constants.S_IWUSR | fs.constants.S_IXUSR | fs.constants.S_IXGRP, (error) => {
				if (error) throw error;
				console.log('/tmp/' + fileName + '.csr permissions has been changed to 710');
			});
		}
	});
}

generateCertificate();