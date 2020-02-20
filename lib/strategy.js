const OAuth2Strategy = require('passport-oauth2');
const util = require('util');
const { InternalOAuthError } = require('passport-oauth2');
const base64 = require('base-64');


function Strategy(options, verify) {
  /* eslint-disable no-param-reassign */
  options = options || {};
  if (options.baseURL) {
    options.authorizationURL = options.authorizationURL || `${options.baseURL}/ms_oauth/oauth2/endpoints/oauthservice/authorize`;
    options.tokenURL = options.tokenURL || `${options.baseURL}/ms_oauth/oauth2/endpoints/oauthservice/tokens`;
    options.profileURL = options.profileURL || `${options.baseURL}/ms_oauth/resources/userprofile/me`;
  }
  options.scope = options.scope || ['UserProfile.me'];
  const authString = base64.encode(`${options.clientID}:${options.clientSecret}`)
  options.customHeaders = {
    Authorization: `Basic ${authString}`,
  };
  /* eslint-enable no-param-reassign */

  OAuth2Strategy.call(this, options, verify);
  this.name = 'oracle';
  this._profileURL = options.profileURL;

  this._oauth2.setAccessTokenName('code');

  this._oauth2.useAuthorizationHeaderforGET(true);

  this._oauth2.buildAuthHeader('');
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = function (accessToken, done) { // eslint-disable-line func-names

  this._oauth2.get(this._profileURL, accessToken, (err, body) => {
    let json;
    if (err) {
      if (err.data) {
        console.error(err.data);
      }
      return done(new InternalOAuthError('Failed to fetch user profile.', err));
    }

    try {
      json = JSON.parse(body);
    } catch (ex) {
      console.error(ex);
      return done(new Error('Failed to parse user profile.'));
    }

    const profile = {};
    profile.provider = 'oracle';
    profile._raw = body; // eslint-disable-line no-underscore-dangle
    profile._json = json; // eslint-disable-line no-underscore-dangle

    return done(null, profile);
  });
};

Strategy.prototype.authorizationParams = function (options) { // eslint-disable-line func-names
  const params = {};
  if (options.state) {
    params.state = options.state;
  }
  return params;
};

module.exports = Strategy;
