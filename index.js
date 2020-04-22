const express = require('express');
const passport = require('passport');
const session = require('express-session');
const redis = require('redis');
const RedisStore = require('connect-redis')(session);
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const passportJWT = require('passport-jwt');

const JWTStrategy = passportJWT.Strategy;
const { ExtractJwt } = passportJWT;
const OAuth2Strategy = require('./lib/strategy');
const config = require('./config/config');
const proxyRequest = require('./controller/proxy');

const app = express();

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(cookieParser());

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

const getToken = (user, timeout) => {
  let userId = null;
  const profileField = config.userProfileId;
  try {
    /* eslint-disable no-underscore-dangle */
    userId = profileField && user._json[profileField]
      ? { [profileField]: user._json[profileField] }
      : user._json;
  } catch (err) {
    userId = user._json;
    /* eslint-enable no-underscore-dangle */
  }
  userId = userId || user;
  return jwt.sign(userId, config.jwtSecret, { expiresIn: timeout });
};

const TOKEN_COOKIE = 'jwt';
const TOKEN_PARAM = 'token';

const setTokenCookie = (res, token) => {
  if (token) {
    res.cookie(TOKEN_COOKIE, token, { maxAge: config.logoutTime, secure: false });
  }
};

const removeTokenCookie = (res) => res.cookie(TOKEN_COOKIE, { expires: Date.now() });

const cookieExtractor = (req) => {
  if (req && req.cookies) {
    const token = req.cookies[TOKEN_COOKIE];
    return token;
  }
  return null;
};

if (config.sessionSecret) {
  let store;
  if (config.redis.host) {
    const client = redis.createClient({ ...config.redis });
    store = new RedisStore({ client });
    console.log(`Using redis store: ${JSON.stringify(store)}`);
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
  }
}


if (config.jwtSecret) {
  const opts = {};
  opts.jwtFromRequest = ExtractJwt.fromExtractors([ExtractJwt.fromAuthHeaderAsBearerToken(),
    ExtractJwt.fromUrlQueryParameter(TOKEN_PARAM), cookieExtractor]);
  opts.secretOrKey = config.jwtSecret;
  passport.use(new JWTStrategy(opts, (jwtPayload, done) => {
    if (Date.now() > jwtPayload.expires) {
      return done('jwt expired');
    }
    if (config.userProfileId && jwtPayload[config.userProfileId]) {
      return done(null, jwtPayload);
    }
    if (jwtPayload) {
      return done(null, jwtPayload);
    }
    return done(null, false);
  }));
}

// After everything is configured initialize passport.
app.use(passport.initialize());
if (config.sessionSecret) {
  app.use(passport.session());
}

if (config.jwtSecret) {
  app.get('/auth/token', (req, res) => res.redirect('/auth/oracle'));
}

const usingOauth = () => !!(config.oauth.authorizationURL || config.oauth.baseURL);
const usingSession = () => !!(config.sessionSecret);

if (usingOauth()) {
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
      { session: usingSession(), scope: config.oauth.scope, state });
    authenticator(req, res, next);
  });

  app.get('/auth/oracle/callback', (req, res, next) => {
    // eslint-disable-next-line consistent-return
    passport.authenticate('oracle', (err, user) => {
      if (err) {
        console.error(err);
        return res.redirect('/auth/logout');
      }
      if (!user) {
        return res.redirect('/auth/logout');
      }

      req.login(user, (loginErr) => {
        if (loginErr) {
          return res.redirect('/auth/logout');
        }

        // If using tokens, add it to the header to allow users to make requests in their browsers.
        let token = null;
        if (config.jwtSecret) {
          const maxAge = config.logoutTime;
          token = getToken(user, maxAge);
        }
        setTokenCookie(res, token);
        const { state } = req.query;
        let returnTo = null;
        if (state) {
          returnTo = Buffer.from(state, 'base64').toString();
        }
        if (req.session) {
          returnTo = returnTo || req.session.returnTo;
          delete req.session.returnTo;
        }
        if (typeof returnTo === 'string' && returnTo.startsWith('/')) {
          return res.redirect(returnTo);
        }
        if (token) {
          // If using tokens, send it to the user as a response (e.g. /token endpoint)
          return res.send({ token });
        }
        return res.redirect('/');
      });
    })(req, res, next);
  });
}


const handleLogout = (req, res) => {
  req.logout();
  removeTokenCookie(res);
  if (config.oauth.logoutURL) {
    return res.redirect(config.oauth.logoutURL);
  }
  return res.redirect('/');
};

app.get('/auth/logout', handleLogout);

const ensureAuthenticated = (req, res, next) => {
  try {
    if (!req.isAuthenticated() && config.jwtSecret) {
      passport.authenticate('jwt', { session: usingSession() }, (err, user) => {
        if (err) {
          console.error(`Error: ${err}`);
        }
        if (user) {
          return next();
        }
        const state = Buffer.from(req.url).toString('base64');
        if (usingOauth()) {
          req.logout();
          return res.redirect(`/auth/oracle?state=${state}`);
        }
        return res.redirect('/auth/logout');
      })(req, res, next);
    } else {
      return next();
    }
  } catch (err) {
    console.error(err);
  }
  return null;
};

const handleReferer = (req, res, next) => {
  // This is used to try to catch traffic which might need to be routed back to a proxied app.
  const hostname = config.host;
  if (req.headers && req.headers.referer) {
    // eslint-disable-next-line no-undef
    const refererUrl = new URL(req.headers.referer);
    if (refererUrl.pathname === '/') {
      // There is no path referer
      return next();
    }
    if (refererUrl.hostname === hostname) {
      const pathRegex = /[^/\\]+/;
      const path = refererUrl.pathname.match(pathRegex)[0];
      if (path in config.proxy) {
        if (!req.path.startsWith(`/${path}/`)) {
          // Send the user to the correct route.
          return res.redirect(`/${path}${req.originalUrl}`);
        }
      }
    }
  }
  return next();
};


const addPath = (entry) => {
  const [path, target] = entry;
  console.log(`Creating Proxy Path for ${path} to ${target}.`);
  const regexPath = `^/${path}(/.*)?*`;
  app.get(regexPath, ensureAuthenticated, proxyRequest(path, target));
};

app.all('*', handleReferer);

Object.entries(config.proxy).forEach(addPath);

app.listen(config.port, () => {
  console.log(`Gateway listening on port ${config.port}...`);
});

module.exports = {
  getToken,
  setTokenCookie,
  removeTokenCookie,
  handleLogout,
  TOKEN_COOKIE,
  TOKEN_PARAM,
  cookieExtractor,
};
