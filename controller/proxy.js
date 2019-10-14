const httpProxy = require('http-proxy');

const apiProxy = httpProxy.createProxyServer();

function proxyRequest(path, target) {
  // eslint-disable-next-line func-names
  return (req, res) => {
    apiProxy.on('proxyReq', (proxyReq, request) => {
      const re = new RegExp(`/${path}(/.*)?$`);
      proxyReq.path = request.url.replace(re, '$1'); // eslint-disable-line no-param-reassign
    });
    apiProxy.web(req, res, { target });
  };
}

module.exports = proxyRequest;
