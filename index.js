/**
 * @module keycloak-request-token
 */

'use strict';

const http = require('http');
const https = require('https');
const url = require('url');
const querystring = require('querystring');

const tokenUrl = 'protocol/openid-connect/token';
const store = new Map();

function ServiceError (status, body, message) {
  this.name = 'ServiceError';
  this.body = body;
  this.status = status;
  this.message = message || 'Invalid request';
  this.stack = (new Error()).stack;
}

ServiceError.prototype = Object.create(Error.prototype);
ServiceError.prototype.constructor = ServiceError;

function getRequestOpts (uri, data) {
  return Object.assign(url.parse(uri), {
    method: 'POST',
    data: data,
    headers: {'Content-type': 'application/x-www-form-urlencoded'}
  });
}

function request (options) {
  const caller = (options.protocol === 'https:') ? https : http;
  const data = [];

  return new Promise(function (resolve, reject) {
    const message = 'Failed to get token';

    const request = caller.request(options, res => {
      res
        .on('data', chunk => data.push(chunk))
        .on('end', () => {
          const {statusCode} = res;

          try {
            const stringData = Buffer.concat(data).toString();

            if (statusCode === 404) {
              return reject(new ServiceError(statusCode, stringData, message));
            }

            const parsedData = JSON.parse(stringData);

            if (statusCode !== 200) {
              return reject(new ServiceError(statusCode, parsedData, message));
            }

            resolve(parsedData);
          } catch (err) {
            reject(err);
          }
        });
    });

    request.on('error', e => reject(e));
    request.write(querystring.stringify(options.data));
    request.end();
  });
}

function getToken (baseUrl, settings) {
  const opts = getRequestOpts(`${baseUrl}/realms/${settings.realmName}/${tokenUrl}`, settings);

  return request(opts);
}

function refreshToken (baseUrl, settings, refreshToken) {
  const data = Object.assign({}, settings, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken
  });

  const opts = getRequestOpts(`${baseUrl}/realms/${settings.realmName}/${tokenUrl}`, data);

  return request(opts);
}

/**
 Requests a new Keycloak Access Token
 @param {string} baseUrl - The baseurl for the Keycloak server - ex: http://localhost:8080/auth,
 @param {object} settings - an object containing the settings
 @param {string} settings.username - The username to login to the keycloak server - ex: admin
 @param {string} settings.password - The password to login to the keycloak server - ex: *****
 @param {string} settings.grant_type - the type of authentication mechanism - ex: password,
 @param {string} settings.client_id - the id of the client that is registered with Keycloak to connect to - ex: admin-cli
 @param {string} settings.realmName - the name of the realm to login to - defaults to 'masterg'
 @returns {Promise} A promise that will resolve with the Access Token String.
 @instance
 @example
 const tokenRequester = require('keycloak-request-token')
 const baseUrl = 'http://127.0.0.1:8080/auth'
 const settings = {
      username: 'admin',
      password: 'admi',
      grant_type: 'password',
      client_id: 'admin-cli'
  }
 tokenRequester(baseUrl, settings)
 .then((token) => {
      console.log(token)
    }).catch((err) => {
      console.log('err', err)
    })
*/

async function tokenRequester (baseUrl, settings = {}) {
  settings.realmName = settings.realmName ? settings.realmName : 'master';

  const storeKey = JSON.stringify(Object.assign({}, settings, {baseUrl}));

  const now = Date.now();

  let token = store.get(storeKey);

  if (token && token.exp > now) {
    return token.access_token;
  }

  if (token && token.refresh_exp > now) {
    token = await refreshToken(baseUrl, settings, token.refresh_token);
  } else {
    token = await getToken(baseUrl, settings);
  }

  token.exp = Date.now() + token.expires_in;
  token.refresh_exp = Date.now() + token.refresh_expires_in;
  store.set(storeKey, token);

  return token.access_token;
}

module.exports = tokenRequester;
