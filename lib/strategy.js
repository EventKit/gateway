const OAuth2Strategy = require('passport-oauth2');
const util = require('util');
const { InternalOAuthError } = require('passport-oauth2');


function Strategy(options, verify) {
  /* eslint-disable no-param-reassign */
  options = options || {};
  if (options.baseURL) {
    options.authorizationURL = options.authorizationURL || `${options.baseURL}/ms_oauth/oauth2/endpoints/oauthservice/authorize`;
    options.tokenURL = options.tokenURL || `${options.baseURL}/ms_oauth/oauth2/endpoints/oauthservice/tokens`;
    options.scope = options.scope || ['UserProfile.me'];
    options.profileURL = options.profileURL || `${options.baseURL}/ms_oauth/resources/userprofile/me`;
  }
  /* eslint-enable no-param-reassign */

  OAuth2Strategy.call(this, options, verify);
  this.name = 'oracle';
  this._profileURL = options.profileURL;

  this._oauth2.setAccessTokenName('code');

  this._oauth2.useAuthorizationHeaderforGET(true);
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = (accessToken, done) => {
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

Strategy.prototype.authorizationParams = (options) => {
  const params = {};
  if (options.state) {
    params.state = options.state;
  }
  return params;
};

module.exports = Strategy;
