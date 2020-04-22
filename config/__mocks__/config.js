const config = {
  port: '8080',
  host: 'localhost',
  logoutTime: 1234, // in ms.
  sessionSecret: 'session secret',
  sessionName: 'session name',
  jwtSecret: 'jwt secret',
  redis: {},
  fileStore: {},
  userProfileId: 'username',
  proxy: { api: 'http://api.test' },
  oauth: {
    baseURL: 'http://oauth.test',
    authorizationURL: '/authorization',
    tokenURL: 'token',
    profileURL: 'profile',
    scope: ['profile'],
    clientID: 'client_id',
    clientSecret: 'client_secret',
    logoutURL: 'logout',
  },
};

module.exports = config;
