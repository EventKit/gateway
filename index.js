const express = require('express');
const passport = require('passport');
const session = require('express-session');
const redis = require('redis');
const RedisStore = require('connect-redis')(session);
const FileStore = require('session-file-store')(session);
const os = require('os');
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

  let store = null
  if (config.redis.host) {
    const client = redis.createClient({ ...config.redis });
    store = new RedisStore({ client });
  } else {
    store = new FileStore({});
  }

  console.warn(`Using a ${store}`);

  app.use(session({
    store,
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: Number(config.logoutTime),
      // secure: true,
    },
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
      console.log(`session: ${request.session}`)
      done(null, profile);
    }
  }));

  app.get('/auth/oracle', (req, res, next) => {
    let state = {};
    if (req.query && req.query.state) {
      state = req.query.state;
    }
    const authenticator = passport.authenticate('oracle', { scope: config.oauth.scope, state });
    authenticator(req, res, next);
  });

  app.get('/auth/oracle/callback', (req, res, next) => {
    passport.authenticate('oracle', (err, user, info) => {

      if (err) {
        return next(err);
      }
      if (!user) {
        console.log("NO USER!")
        return res.redirect('/');
      }
      req.logIn(user, (err) => {
        console.log(`logging in: ${JSON.stringify(user)}`)
        if (err) {
          console.log('log in error')

          return next(err);
        }
        const { state } = req.query;
        let returnTo = Buffer.from(state, 'base64').toString();
        if (typeof returnTo === 'string' && returnTo.startsWith('/')) {
          return res.redirect(returnTo);
        }
        console.log('No redirect... sending to root.')
        returnTo = req.session.returnTo;
        delete req.session.returnTo;
        res.redirect(returnTo || '/');
      });
    })(req, res, next);
      // console.warn(`Allowing access for: ${JSON.stringify(req.user)}`);
      // try {
      //   const {state} = req.query;
      //   const returnTo = Buffer.from(state, 'base64').toString();
      //   if (typeof returnTo === 'string' && returnTo.startsWith('/')) {
      //     return res.redirect(returnTo);
      //   }
      // } catch (ex) {
      //   // continue regardless of error
      // }
      // return res.redirect('/');
    // })(req, res, next);
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
  console.log(`HOSTNAME: ${os.hostname()}`);
  console.log(`req:${Object.keys(req)}`)
  if (req.user) {
    return next();
  }
  // if (usingOauth()) {
  //   const state = Buffer.from(req.url).toString('base64');
  //   return res.redirect(`/auth/oracle?state=${state}`);
  // }
  // c

  return res.send('Please login at /auth/oracle to view this content.');
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
