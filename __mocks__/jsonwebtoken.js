const jwt = {};
const returnedToken = 'token';
jwt.sign = jest.fn().mockReturnValue(returnedToken);

module.exports = jwt;
