const httpProxy = require('http-proxy');

function proxyRequest(path, target) {
  const apiProxy = httpProxy.createProxyServer();
  // eslint-disable-next-line func-names
  return (req, res) => {
    apiProxy.on('proxyReq', (proxyReq, request) => {
      const re = new RegExp(`/${path}(/.*)?$`);
      proxyReq.path = request.url.replace(re, '$1'); // eslint-disable-line no-param-reassign
    });
    apiProxy.on('proxyRes', (proxyRes, request) => {
      if (proxyRes.headers.location) {
        // We want to redirect the user back to the correct server,
        // unless the server points to itself.
        if (!proxyRes.headers.location.includes(request.path)) {
          proxyRes.headers.location = `/${path}${proxyRes.headers.location}`; // eslint-disable-line no-param-reassign
        }
      }
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
