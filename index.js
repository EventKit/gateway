const express = require('express');
const passport = require('passport');
const session = require('express-session');
const redis = require('redis');
const RedisStore = require('connect-redis')(session);
const FileStore = require('session-file-store')(session);
const fs = require('fs');
const cookieParser = require('cookie-parser');
const OAuth2Strategy = require('./lib/strategy');
const config = require('./config/config');
const proxyRequest = require('./controller/proxy');

const app = express();

app.set('trust proxy', 1);

if (config.sessionSecret) {
  passport.serializeUser((user, done) => {
    done(null, user);
  });

  passport.deserializeUser((obj, done) => {
    done(null, obj);
  });

  let store;
  if (config.redis.host) {
    const client = redis.createClient({ ...config.redis });
    store = new RedisStore({ client });
    console.log(`Using redis store: ${JSON.stringify(store)}`);
  } else {
    if (config.fileStore.path) {
      if (!fs.existsSync(config.fileStore.path)) {
        fs.mkdirSync(config.fileStore.path);
      }
    } else if (process.env.VCAP_SERVICES) {
      // If not using a common file path then use sticky sessions.
      config.sessionName = 'JSESSIONID';
    }
    store = new FileStore(config.fileStore);
    console.log(`Using file store: ${JSON.stringify(store)}`);
  }

  app.use(session({
    store,
    name: config.sessionName,
    secret: config.sessionSecret,
    genid: config.sessionGenId,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: Number(config.logoutTime),
      secure: true,
    },
  }));
  app.use(passport.initialize());
  app.use(passport.session());
}

// Set cookie if using PCF
app.use(cookieParser());

// This is used for PCF sticky sessions.
app.use((req, res, next) => {
  // eslint-disable-next-line no-underscore-dangle
  const cookie = req.cookies.__VCAP_ID__;
  if (cookie !== undefined) {
    res.cookie('__VCAP_ID__', cookie, { maxAge: Number(config.logoutTime), secure: true });
  }
  next();
});

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
    if (accessToken || profile) {
      done(null, profile);
    }
  }));

  app.get('/auth/oracle', (req, res, next) => {
    let state = {};
    if (req.query && req.query.state) {
      state = req.query.state;
    }
    const authenticator = passport.authenticate('oracle',
      { session: true, scope: config.oauth.scope, state });
    authenticator(req, res, next);
  });

  app.get('/auth/oracle/callback', (req, res, next) => {
    // eslint-disable-next-line consistent-return
    passport.authenticate('oracle', (err, user) => {

      if (err) {
        console.error(err)
        return res.redirect('/auth/logout');
      }
      if (!user) {
        return res.redirect('/');
      }
      req.logIn(user, (loginError) => {
        console.log(`Logging in: ${JSON.stringify(user)}`);
        if (loginError) {
          console.error(loginError.request.message);
          return next(loginError);
        }
        const { state } = req.query;
        let returnTo = Buffer.from(state, 'base64').toString();
        if (typeof returnTo === 'string' && returnTo.startsWith('/')) {
          return res.redirect(returnTo);
        }
        returnTo = req.session.returnTo;
        delete req.session.returnTo;
        return res.redirect(returnTo || '/');
      });
    })(req, res, next);
  });
}

app.get('/auth/logout', (req, res) => {
  req.logout();
  if (config.oauth.logoutURL) {
    return res.redirect(config.oauth.logoutURL);
  }
  return res.redirect('/');
});

const ensureAuthenticated = (req, res, next) => {
  try {
    if (req.isAuthenticated()) {
      return next();
    }
  } catch (err) {
    return res.redirect('/auth/logout');
  }
  const state = Buffer.from(req.url).toString('base64');
  if (usingOauth()) {
    req.logout();
    return res.redirect(`/auth/oracle?state=${state}`);
  }
  return res.redirect('/auth/logout');
};

const addPath = (entry) => {
  const [path, target] = entry;
  console.log(`Creating Proxy Path for ${path} to ${target}.`);
  const regexPath = `^/${path}(/.*)?*`;
  app.get(regexPath, ensureAuthenticated, proxyRequest(path, target));
};

Object.entries(config.proxy).forEach(addPath);

app.listen(config.port, () => {
  console.log(`Gateway listening on port ${config.port}...`);
});
