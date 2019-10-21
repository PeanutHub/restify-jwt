const jwt = require("jsonwebtoken");
const unless = require("express-unless");
const async = require("async");

const ForbiddenError = require("restify-errors").ForbiddenError;
const UnauthorizedError = require("restify-errors").UnauthorizedError;
const InvalidCredentialsError = require("restify-errors").InvalidCredentialsError;
const errors = require("./errors");

const DEFAULT_REVOKED_FUNCTION = function(_, __, cb) {
  return cb(null, false);
};

const getClass = {}.toString;

function isFunction(object) {
  return object && getClass.call(object) == "[object Function]";
}

function wrapStaticSecretInCallback(secret) {
  return function(_, __, cb) {
    return cb(null, secret);
  };
}

module.exports = function(options) {
  if (!options || !options.secret) throw new Error("secret should be set");

  const enableApiKeys = options.enableApiKeys === true;

  let secretCallback = options.secret;

  if (!isFunction(secretCallback)) {
    secretCallback = wrapStaticSecretInCallback(secretCallback);
  }

  const isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;

  const _requestProperty = options.userProperty || options.requestProperty || "user";
  const credentialsRequired = typeof options.credentialsRequired === "undefined" ? true : options.credentialsRequired;

  const schemesSupported = enableApiKeys ? /^Bearer|ApiKey$/i : /^Bearer$/i;
  const schemesEnum = {
    BEARER: 1,
    APIKEY: 2
  };
  const middleware = function(req, res, next) {
    let token;
    let token_type = schemesEnum.BEARER;

    if (req.method === "OPTIONS" && req.headers.hasOwnProperty("access-control-request-headers")) {
      const hasAuthInAccessControl = !!~req.headers["access-control-request-headers"]
        .split(",")
        .map(function(header) {
          return header.trim();
        })
        .indexOf("authorization");

      if (hasAuthInAccessControl) {
        return next();
      }
    }

    if (options.getToken && typeof options.getToken === "function") {
      try {
        token = options.getToken(req);
      } catch (e) {
        return next(e);
      }
    } else if (req.headers && req.headers.authorization) {
      const parts = req.headers.authorization.split(" ");
      if (parts.length == 2) {
        const scheme = parts[0];
        const credentials = parts[1];

        if (schemesSupported.test(scheme)) {
          if (scheme.indexOf("apikey") >= 0) {
            token_type = schemesEnum.APIKEY;
          }

          token = credentials;
        } else {
          return next(new InvalidCredentialsError("Format is Authorization: [token_type] [token]"));
        }
      } else {
        return next(new InvalidCredentialsError("Format is Authorization: [token_type] [token]"));
      }
    } else if (enableApiKeys && req.headers && (req.headers["x-api-key"] || req.headers["api-key"])) {
      token_type = schemesEnum.APIKEY;
      token = req.headers["x-api-key"] || req.headers["api-key"];
    } else if (enableApiKeys && req.query && req.query["apikey"]) {
      token_type = schemesEnum.APIKEY;
      token = req.query["apikey"];
    } else if (req.query && req.query["access_token"]) {
      token_type = schemesEnum.BEARER;
      token = req.query["access_token"];
    }

    if (!token) {
      if (credentialsRequired) {
        return next(new InvalidCredentialsError("No authorization token was found"));
      } else {
        return next();
      }
    }

    const dtoken =
      jwt.decode(token, {
        complete: true
      }) || {};

    // CHECK IF THE TOKEN HAVE THE BEARER TYPE!
    if (
      token_type === schemesEnum.APIKEY &&
      (!dtoken.payload || (dtoken.payload && dtoken.payload.type !== "ApiKey"))
    ) {
      return next(new InvalidCredentialsError("The authorization token is not an APIKEY"));
    }

    async.parallel(
      [
        function(callback) {
          const arity = secretCallback.length;
          if (arity == 4) {
            secretCallback(req, dtoken.header, dtoken.payload, callback);
          } else {
            // arity == 3
            secretCallback(req, dtoken.payload, callback);
          }
        },
        function(callback) {
          isRevokedCallback(req, dtoken.payload, callback);
        }
      ],
      function(err, results) {
        if (err) {
          return next(err);
        }
        const revoked = results[1];
        if (revoked) {
          return next(new UnauthorizedError("The token has been revoked."));
        }

        const secret = results[0];

        jwt.verify(token, secret, options, function(err, decoded) {
          if (err && credentialsRequired) return next(new InvalidCredentialsError(err));

          decoded.checkIAM = function(rolesToCheck, application, allowedGroupSids) {
            return new Promise((resolve, reject) => {
              const allowedRoles = Array.isArray(rolesToCheck) ? rolesToCheck : [rolesToCheck];
              const allowedGroups = allowedGroupSids
                ? Array.isArray(allowedGroupSids)
                  ? allowedGroupSids
                  : [allowedGroupSids]
                : ["USER", "APPL"];

              // Check if allowed groups are permitted to do the action
              let isGroupAllowed = false;
              if (allowedGroups) {
                isGroupAllowed = allowedGroups.some(function(item) {
                  return item == decoded.groupsid;
                });
              }

              if (!isGroupAllowed) {
                return reject(
                  new errors.ForbiddenError(
                    "Groupsid for the JWT is not permitted to do the action",
                    allowedRoles,
                    allowedGroups
                  )
                );
              }

              // If the identity dont have scope
              if (!decoded.scope) {
                return reject(
                  new errors.ForbiddenError(
                    "Role for the JWT is not permitted to do the action",
                    allowedRoles,
                    allowedGroups
                  )
                );
              }

              // Check if allowed roles are permitted to do the action
              let isRoleAllowed = false;
              const scopesToCheck = [];
              allowedRoles.forEach(function(role) {
                scopesToCheck.push(`${application}:${role}`);
              });

              // Find the first coincidence for the role to check
              // if match , break the loop because the identity has the role to do the action
              for (const scopeIndex in scopesToCheck) {
                const scopeToCheck = scopesToCheck[scopeIndex];
                if (decoded.scope.indexOf(scopeToCheck) >= 0) {
                  isRoleAllowed = true;
                  break;
                }
              }

              if (!isRoleAllowed) {
                return reject(
                  new errors.ForbiddenError(
                    "Role for the JWT is not permitted to do the action",
                    allowedRoles,
                    allowedGroups
                  )
                );
              }

              resolve(true);
            });
          };

          if (options.allowedClientIds) {
            let isAllowed = false;

            for (let idx = 0; idx < options.allowedClientIds.length; idx++) {
              const clientId = options.allowedClientIds[idx];
              const hasAtLeastOneScopeOfClient = new RegExp(`${clientId}:[a-z]{1,}`).test(decoded.scope);
              if (hasAtLeastOneScopeOfClient) {
                isAllowed = true;
              }
              idx++;
            }
            if (!isAllowed) {
              return next(
                new ForbiddenError(
                  `The token has been rejected, you need at least one scope with the following clients [${options.allowedClientIds.join(
                    ","
                  )}].`
                )
              );
            }
          }

          req[_requestProperty] = decoded;
          next();
        });
      }
    );
  };

  middleware.unless = unless;

  return middleware;
};
