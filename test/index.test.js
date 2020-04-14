const {
  getToken, setTokenCookie, TOKEN_COOKIE, handleLogout,
  cookieExtractor, removeTokenCookie,
} = require('../index.js');

jest.mock('../config/config');
jest.mock('express');
jest.mock('jsonwebtoken');
jest.mock('jsonwebtoken');

const getMockRequest = (sessionData) => {
  const req = {};
  req.logout = jest.fn().mockReturnValue(req);
  req.session = { data: sessionData };
  return req;
};

const getMockResponse = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.cookie = jest.fn().mockReturnValue(res);
  res.redirect = jest.fn().mockReturnValue(res);
  const token = 'token';
  const cookies = {};
  cookies[TOKEN_COOKIE] = token;
  res.cookies = cookies;
  return res;
};

test('setTokenCookie adds a token to the cookie', () => {
  const exampleToken = 'token';
  const res = getMockResponse();
  setTokenCookie(res, exampleToken);
  expect(res.cookie).toHaveBeenCalledWith(TOKEN_COOKIE,
    exampleToken,
    { maxAge: 1234, secure: false });
});

test('getToken returns a jwt', () => {
  const timeout = 21;
  const username = 'testuser';
  const user = { __json: { username } };
  const token = getToken(user, timeout);
  expect(token).toBe('token');
});

test('cookie extractor returns the token from the request.', () => {
  expect(cookieExtractor(getMockResponse())).toBe('token');
});

test('removeTokenCookie causes the token cookie to expire immediately', () => {
  const res = getMockResponse();
  const dateNowStub = jest.fn(() => 1586891941652);
  global.Date.now = dateNowStub;
  removeTokenCookie(res);
  expect(res.cookie).toHaveBeenCalledWith(TOKEN_COOKIE, { expires: dateNowStub() });
});

test('handleLogout clears the user session, clears jwt token, and redirects to the logout url', () => {
  const req = getMockRequest();
  const res = getMockResponse();
  handleLogout(req, res);
  expect(req.logout).toHaveBeenCalledTimes(1);
  expect(res.redirect).toHaveBeenCalledWith('logout');
});
