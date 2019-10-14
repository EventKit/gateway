const express = require('express');
const passport = require('passport');
const session = require('express-session');
const redis = require('redis');
const RedisStore = require('connect-redis')(session);
const OAuth2Strategy = require('./lib/strategy');
const config = require('./config/config');
const proxyRequest = require('./controller/proxy');


const app = express();

if (config.sessionSecret) {
  passport.serializeUser((user, done) => {
    done(null, user);
  });

  passport.deserializeUser((obj, done) => {
    done(null, obj);
  });

  const client = redis.createClient({ ...config.redis });

  app.use(session({
    store: new RedisStore({ client }),
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: Number(config.logoutTime) },
  }));
  app.use(passport.initialize());
  app.use(passport.session());
}

const usingOauth = () => !!(config.oauth.authorizationURL || config.oauth.baseURL);

if (usingOauth()) {
  if (!config.sessionSecret) {
    throw Error('Cannot use Oauth without configuring SESSION_SECRET');
  }
  // TODO: allow other strategies and/or multiple oauth
  passport.use(new OAuth2Strategy({
    ...config.oauth,
    callbackURL: `https://${config.host}/auth/oracle/callback`,
  },
  (request, accessToken, refreshToken, profile, done) => {
    if (accessToken) {
      done(null, profile);
    }
  }));

  app.get('/auth/oracle', (req, res, next) => {
    let state = {};
    if (req.query && req.query.state) {
      state = req.query.state;
    }
    const authenticator = passport.authenticate('oracle', { scope: ['openid', 'profile'], state });

    authenticator(req, res, next);
  });

  app.get('/auth/oracle/callback',
    passport.authenticate('oracle'),
    (req, res) => {
      try {
        const { state } = req.query;
        const returnTo = Buffer.from(state, 'base64').toString();
        if (typeof returnTo === 'string' && returnTo.startsWith('/')) {
          return res.redirect(returnTo);
        }
      } catch (ex) {
        // continue regardless of error
      }
      return res.redirect('/');
    });
}

app.get('/logout', (req, res) => {
  req.logout();
  if (config.oauth.logoutURL) {
    return res.redirect(config.oauth.logoutURL);
  }
  return res.redirect('/');
});

const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }

  const state = Buffer.from(req.url).toString('base64');
  if (usingOauth()) {
    return res.redirect(`/auth/oracle?state=${state}`);
  }
  return next();
};

const addPath = (entry) => {
  const [path, target] = entry;
  console.log(`Creating Proxy Path for ${path} to ${target}.`);
  const regexPath = `^/${path}(/.*)?*`;
  app.get(regexPath, ensureAuthenticated, proxyRequest(path, target));
}

Object.entries(config.proxy).forEach(addPath);

app.listen(config.port, () => {
  console.log(`Gateway listening on port ${config.port}...`);
});
