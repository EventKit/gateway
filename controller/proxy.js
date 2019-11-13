const httpProxy = require('http-proxy');

const apiProxy = httpProxy.createProxyServer();

function proxyRequest(path, target) {
  // eslint-disable-next-line func-names
  return (req, res) => {
    apiProxy.on('proxyReq', (proxyReq, request) => {
      const re = new RegExp(`/${path}(/.*)?$`);
      proxyReq.path = request.url.replace(re, '$1'); // eslint-disable-line no-param-reassign
    });
    apiProxy.on('error', (error, proxyReq, proxyRes) => {
      try {
        proxyRes.writeHead(500, {
          'Content-Type': 'application/json',
        });
        proxyRes.end(JSON.stringify({ error: 'Unable to reach that URL. Please contact an administrator.' }));
      } catch (err) {
        // Response already sent carry on.
      }
    });
    apiProxy.web(req, res, { target });
  };
}

module.exports = proxyRequest;
