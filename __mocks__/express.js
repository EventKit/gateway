const express = () => ({
  set: () => jest.fn().mockReturnValue(null),
  disable: () => jest.fn().mockReturnValue(null),
  use: () => jest.fn().mockReturnValue(null),
  get: () => jest.fn().mockReturnValue(null),
  listen: () => jest.fn().mockReturnValue(null),
});


module.exports = express;
