const tokenRequester = require('./');

const baseUrl = 'http://keycloak:8180/auth';

const settings = {
  'grant_type': 'client_credentials',
  'client_id': 'zcts-ui',
  'client_secret': '99c4c60d-03ed-486b-8021-ab43f9698673'
};

(async function () {
  try {
    const token = await tokenRequester(baseUrl, settings);
    console.log(token);
  } catch (err) {
    console.log('err', err);
  }
})();
