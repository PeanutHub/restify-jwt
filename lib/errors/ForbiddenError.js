'use strict';
const AbstractError = require('./AbstractError');

/**
 * Define a Generic Error
 */
class ForbiddenError extends AbstractError {
  /**
   * Create a Bad Request Generic Error
   * @param {String} errorDescription Error message description for verbose description
   * @param {Object} metaData single object with additional data to attach in the exception
   */
  constructor(errorDescription, allowedRoles, allowedGroups) {
    super('FORBIDDEN_ACCESS', errorDescription, {
      'allowed_roles': allowedRoles.join(','),
      'allowed_groups': allowedGroups.join(','),
    });

    // Set the http status code
    this.statusCode = 403;
  }
}

module.exports = ForbiddenError;
