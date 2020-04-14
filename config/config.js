const path = require('path');

// Set a default config
let config = {
  port: '8080',
  host: 'localhost',
  logoutTime: '1200000', // in ms.
  sessionSecret: null,
  sessionName: null,
  jwtSecret: null,
  redis: {},
  fileStore: {},
  userProfileId: 'username',
  proxy: {}, // example: {'api': 'http://myapi.test/'}
  oauth: {
    baseURL: null,
    authorizationURL: null,
    tokenURL: null,
    profileURL: null,
    scope: [],
    clientID: null,
    clientSecret: null,
    logoutURL: null,
  },
};

// Use params if they can be intuited from the deployment environment.

if (process.env.VCAP_SERVICES) {
  const services = JSON.parse(process.env.VCAP_SERVICES);
  if (services['od.redis']) {
    const redisConfig = services['od.redis'][0].credentials;
    config.redis.host = redisConfig.host;
    config.redis.port = redisConfig.port;
    config.redis.password = redisConfig.password;
  }
  if (services['p-identity']) {
    const identityConfig = services['p-identity'][0].credentials;
    config.oauth.baseURL = identityConfig.auth_domain;
    config.oauth.clientID = identityConfig.client_id;
    config.oauth.clientSecret = identityConfig.client_secret;
  }
  if (services.nfs) {
    config.fileStore.path = path.join(services.nfs[0].volume_mounts[0].container_dir, 'pelias');
  }
}

// Use params defined in the environment.
config = process.env.GATEWAY_CONFIG ? JSON.parse(process.env.GATEWAY_CONFIG) : config;
config.port = process.env.PORT || config.port;
config.host = process.env.HOST || config.host;
config.logoutTime = (Number(process.env.LOGOUT_TIME) * 1000) || config.logoutTime;
config.fileStore.ttl = (Number(config.logoutTime) / 1000);
config.sessionSecret = process.env.SESSION_SECRET;
config.jwtSecret = process.env.JWT_SECRET;
config.userProfileId = process.env.USER_PROFILE_ID;
config.proxy = process.env.PROXY ? JSON.parse(process.env.PROXY) : config.proxy;
config.redis.host = process.env.REDIS_HOST || config.redis.host;
config.redis.port = process.env.REDIS_PORT || config.redis.port;
config.redis.password = process.env.REDIS_PASSWORD || config.redis.password;
config.redis.db = process.env.REDIS_DB || config.redis.db;
config.oauth.baseURL = process.env.OAUTH_BASE_URL || config.oauth.baseURL;
config.oauth.authorizationURL = process.env.OAUTH_AUTHORIZATION_URL
  || config.oauth.authorizationURL;
config.oauth.tokenURL = process.env.OAUTH_TOKEN_URL || config.oauth.tokenURL;
config.oauth.profileURL = process.env.OAUTH_PROFILE_URL || config.oauth.profileURL;
config.oauth.scope = process.env.OAUTH_SCOPE ? JSON.parse(process.env.OAUTH_SCOPE)
  : config.oauth.scope;
config.oauth.clientID = process.env.OAUTH_CLIENT_ID ? process.env.OAUTH_CLIENT_ID
  : config.oauth.clientID;
config.oauth.clientSecret = process.env.OAUTH_CLIENT_SECRET ? process.env.OAUTH_CLIENT_SECRET
  : config.oauth.clientSecret;
config.oauth.logoutURL = process.env.OAUTH_LOGOUT_URL ? process.env.OAUTH_LOGOUT_URL
  : config.oauth.logoutURL;


module.exports = config;
