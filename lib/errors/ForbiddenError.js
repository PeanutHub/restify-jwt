const AbstractError = require("./AbstractError");

/**
 * Define a Generic Error
 */
class ForbiddenError extends AbstractError {
  /**
   * Create a Bad Request Generic Error
   * @param {String} errorDescription Error message description for verbose description
   * @param {Object} metaData single object with additional data to attach in the exception
   */
  constructor(errorDescription, allowedRoles, allowedGroups, allowedApplication) {
    super("FORBIDDEN_ACCESS", errorDescription, {});

    const allows = {
      allowed_roles: allowedRoles.join(","),
      allowed_groups: allowedGroups.join(","),
      allowed_application: allowedApplication
    };
    if (!allows.allowed_roles) {
      delete allows.allowed_roles;
    }
    if (!allows.allowed_groups) {
      delete allows.allowed_groups;
    }
    if (!allows.allowed_application) {
      delete allows.allowed_application;
    }

    this["meta_data"] = allows;
    // Set the http status code
    this.statusCode = 403;
  }
}

module.exports = ForbiddenError;
