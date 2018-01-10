'use strict';

// Load config from .env file.
require('dotenv').config();

// Determine the port we'll listen on.
const port = (process.env.PORT) ? process.env.PORT : 80;

// Check all required env vars are present.
if (!process.env.GITHUB_ACCESS_TOKEN) { console.error('Missing Environment Variable', 'GITHUB_ACCESS_TOKEN'); process.exit(); }
if (!process.env.MAILGUN_KEY) { console.error('Missing Environment Variable', 'MAILGUN_KEY'); process.exit(); }

// Load dependencies.
const crypto = require('crypto');
const express = require('express');
const app = express();
const ghks = require('ghks');
const mailgun = require('mailgun-js')({ apiKey: process.env.MAILGUN_KEY, domain: process.env.MAILGUN_DOMAIN });
const emailvalidator = require('email-validator');

/*
 * /hit/
 * Receives a hit from the non-whitelisted origin.
 */
app.get( '/hit/', (req, res) => {

	// Always send CORS headers.
	res.header( 'Access-Control-Allow-Origin', '*' );
	res.header( 'Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept' );

	// Check both of our parameters exist.
	if ( ! req.query.key ) return res.json( { status: 'error', message: 'Missing key parameter.' } );
	if ( !req.query.origin ) return res.json( { status: 'error', message: 'Missing origin parameter.' } );

	// Get the key / origin stores and check the key exists.
	let keyStore = ( cache.get( 'keys' ) ) ? cache.get( 'keys' ) : {}
		,	originStore = ( cache.get( 'origins' ) ) ? cache.get( 'origins' ) : {};

	// Check if the key is valid.
	if ( !keyStore.hasOwnProperty( req.query.key ) ) return res.json( { status: 'error', message: 'Invalid key parameter.' } );

	// Check if a notification is required.
	if (
		( !originStore.hasOwnProperty( req.query.key ) ) || // If we don't know about this key...
		( originStore.hasOwnProperty( req.query.key ) && ! originStore[req.query.key].hasOwnProperty( req.query.origin ) ) // Or we know about the key, but not the origin.
	) {

		// Build the user-agent block.
		let uaNotice = '';
		if ( req.headers['user-agent'] ) {
			uaNotice = `
				<p>The user agent which loaded the page when I detected it was:</p>
				<pre>${req.headers['user-agent'].replace(/<\/?[^>]+(>|$)/g, '')}</pre>
			`;
		}

		// Build the notification.
		let message = {
			from: 'DomainCanary <noreply@domaincanary.co>',
			to: keyStore[req.query.key],
			subject: 'DomainCanary found a duplicate domain!',
			html: `
				<p>Hi there,</p>
				<p>Just a quick email to let you know that I've spotted your website is loading from ${req.query.origin.replace(/<\/?[^>]+(>|$)/g,'')} - an origin which isn't in the whitelist you gave me!</p>
				${uaNotice}
				<p>I've made a note that I've sent you this email, so I won't bother you again.</p>
				<p>If I was helpful, please let my owner know on Twitter - <a href="https://twitter.com/simon_jthompson">@simon_jthompson</a>.</p>
				<p><b>DomainCanary</b></p>
			`
		};

		// Send the notification.
		mailgun.messages().send( message, (error, body) => {

			// Something went wrong. Fail.
			if (error) return res.json( { status: 'error', message: 'Failed to send notification.' } );

			// Add this hit to the origin store.
			if (!originStore.hasOwnProperty(req.query.key)) originStore[req.query.key] = {};
			originStore[req.query.key][req.query.origin] = true;

			// Update our originStore.
			cache.set( 'origins', originStore );

			// Trigger a manual cache push to ensure it's copied up.
			cache.push();

			// Return ok.
			return res.json( { status: 'ok' } );
		} );
	}else{
		
		// Return ok.
		res.json( {status: 'ok'} );
	}
} );

/*
 * /register/
 * Registers an email token.
 */
app.get( '/register/', (req, res) => {
	
	// Always send CORS headers.
	res.header( 'Access-Control-Allow-Origin', '*' );
	res.header( 'Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept' );

	// Check our parameters exists.
	if ( !req.query.email || !emailvalidator.validate( req.query.email ) ) return res.send( 'Unable to generate token.' );

	// Generate the email token.
	let token = crypto.createHash('md5').update(req.query.email).digest('hex').toString();

	// Update the keystore.
	let keyStore = ( cache.get( 'keys' ) ) ? cache.get( 'keys' ) : {};
	keyStore[token] = req.query.email;
	cache.set( 'keys', keyStore );

	// Trigger a manual cache push to ensure it's copied up.
	cache.push();

	// Return ok.
	res.send( token );
} );

// Setup the persistent cache in a GitHub gist.
const cache = new ghks( {
	name: 'domaincanary_cache',
	token: process.env.GITHUB_ACCESS_TOKEN
} );

// Init the cache.
cache.init().then(function () {

	// Start listening!
	console.info('🐤 domaincanary is listening on port ' + port);
	app.listen(port);
}).catch(function (error) { console.error('Failed to init cache', error); process.exit(); });