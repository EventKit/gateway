const OAuth2Strategy = require('../../lib/strategy');


const baseConfig = {
  baseURL: 'http://test.test',
  authorizationURL: 'http://test.test/authorize',
  tokenURL: 'http://test.test/token',
  profileURL: 'http://test.test/profile',
  scope: ['profile'],
  clientID: 'ID',
  clientSecret: 'SECRET',
  logoutURL: 'http://test.test/logout',
};

test('Contructor works.', () => {
  const strategy = new OAuth2Strategy({
    ...baseConfig,
  },
  (() => {}));

  expect(strategy.name).toBe('oracle');
});

test('Constructed with undefined options blows up.', () => {
  expect(() => {
    OAuth2Strategy(undefined, () => {});
  }).toThrow(Error);
});
