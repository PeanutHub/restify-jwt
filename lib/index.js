var jwt = require('jsonwebtoken');
var unless = require('express-unless');
var restify = require('restify');
var async = require('async');

var InvalidCredentialsError = require('restify-errors').InvalidCredentialsError;

var DEFAULT_REVOKED_FUNCTION = function (_, __, cb) { return cb(null, false); };

var getClass = {}.toString;
function isFunction(object) {
  return object && getClass.call(object) == '[object Function]';
}

function wrapStaticSecretInCallback(secret) {
  return function (_, __, cb) {
    return cb(null, secret);
  };
}

module.exports = function (options) {
  if (!options || !options.secret) throw new Error('secret should be set');

  var enableApiKeys = (options.enableApiKeys === true);

  var secretCallback = options.secret;

  if (!isFunction(secretCallback)) {
    secretCallback = wrapStaticSecretInCallback(secretCallback);
  }

  var isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;

  var _requestProperty = options.userProperty || options.requestProperty || 'user';
  var credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired;

  const schemesSupported = enableApiKeys ? /^Bearer|ApiKey$/i : /^Bearer$/i;
  const schemesEnum = {
    BEARER: 1,
    APIKEY: 2
  };
  var middleware = function (req, res, next) {
    var token;
    var token_type = schemesEnum.BEARER;

    if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) {
      var hasAuthInAccessControl = !!~req.headers['access-control-request-headers']
        .split(',').map(function (header) {
          return header.trim();
        }).indexOf('authorization');

      if (hasAuthInAccessControl) {
        return next();
      }
    }

    if (options.getToken && typeof options.getToken === 'function') {
      try {
        token = options.getToken(req);
      } catch (e) {
        return next(e);
      }
    } else if (req.headers && req.headers.authorization) {
      var parts = req.headers.authorization.split(' ');
      if (parts.length == 2) {
        var scheme = parts[0];
        var credentials = parts[1];

        if (schemesSupported.test(scheme)) {
          if (scheme.indexOf("apikey") >= 0) {
            token_type = schemesEnum.APIKEY
          };

          token = credentials;
        } else {
          return next(new InvalidCredentialsError('Format is Authorization: [token_type] [token]'));
        }
      } else {
        return next(new InvalidCredentialsError('Format is Authorization: [token_type] [token]'));
      }
    } else if (enableApiKeys && req.headers && (req.headers['x-api-key'] || req.headers['api-key'])) {
      token_type = schemesEnum.APIKEY;
      token = (req.headers['x-api-key'] || req.headers['api-key']);
    }

    if (!token) {
      if (credentialsRequired) {
        return next(new InvalidCredentialsError('No authorization token was found'));
      } else {
        return next();
      }
    }

    var dtoken = jwt.decode(token, { complete: true }) || {};

    //CHECK IF THE TOKEN HAVE THE BEARER TYPE!
    if (token_type === schemesEnum.APIKEY && dtoken.payload.type !== "ApiKey") {
      return next(new InvalidCredentialsError('The authorization token is not an APIKEY'));
    }

    async.parallel([
      function (callback) {
        var arity = secretCallback.length;
        if (arity == 4) {
          secretCallback(req, dtoken.header, dtoken.payload, callback);
        } else { // arity == 3
          secretCallback(req, dtoken.payload, callback);
        }
      },
      function (callback) {
        isRevokedCallback(req, dtoken.payload, callback);
      }
    ], function (err, results) {
      if (err) { return next(err); }
      var revoked = results[1];
      if (revoked) {
        return next(new restify.UnauthorizedError('The token has been revoked.'));
      }

      var secret = results[0];

      jwt.verify(token, secret, options, function (err, decoded) {
        if (err && credentialsRequired) return next(new InvalidCredentialsError(err));

        req[_requestProperty] = decoded;
        next();
      });
    });
  };

  middleware.unless = unless;

  return middleware;
};
