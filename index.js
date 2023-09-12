/*!
 * Forked from expressjs/csrf September 2023
 * csurf
 * Copyright(c) 2011 Sencha Inc.
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2014-2016 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 * @private
 */
var createError = require('http-errors')
var Tokens = require('csrf')

/**
 * Module exports.
 * @public
 */

module.exports = csurf

/**
 * CSRF protection middleware.
 *
 * This middleware adds a `req.csrfToken()` function to make a token
 * which should be added to requests which mutate
 * state, within a hidden form field, query-string etc. This
 * token is validated against the visitor's session.
 *
 * @param {Object} options
 * @return {Function} middleware
 * @public
 */

function csurf (options) {
  var opts = options || {}

  // get session options
  var sessionKey = opts.sessionKey || 'session'

  // get value getter
  var value = opts.value || defaultValue

  // token repo
  var tokens = new Tokens(opts)

  // ignored methods
  var ignoreMethods = opts.ignoreMethods === undefined
    ? ['GET', 'HEAD', 'OPTIONS']
    : opts.ignoreMethods

  if (!Array.isArray(ignoreMethods)) {
    throw new TypeError('option ignoreMethods must be an array')
  }

  // generate lookup
  var ignoreMethod = getIgnoredMethods(ignoreMethods)

  return function csrf (req, res, next) {
    // validate the configuration against request
    if (!verifyConfiguration(req, sessionKey)) {
      return next(new Error('misconfigured csrf'))
    }

    // get the secret from the request
    var secret = getSecret(req, sessionKey)
    var token

    // lazy-load token getter
    req.csrfToken = function csrfToken () {
      var sec = getSecret(req, sessionKey)

      // use cached token if secret has not changed
      if (token && sec === secret) {
        return token
      }

      // generate & set new secret
      if (sec === undefined) {
        sec = tokens.secretSync()
        setSecret(req, res, sessionKey, sec)
      }

      // update changed secret
      secret = sec

      // create new token
      token = tokens.create(secret)

      return token
    }

    // generate & set secret
    if (!secret) {
      secret = tokens.secretSync()
      setSecret(req, res, sessionKey, secret)
    }

    // verify the incoming token
    if (!ignoreMethod[req.method] && !tokens.verify(secret, value(req))) {
      return next(createError(403, 'invalid csrf token', {
        code: 'EBADCSRFTOKEN'
      }))
    }

    next()
  }
}

/**
 * Default value function, checking the `req.body`
 * and `req.query` for the CSRF token.
 *
 * @param {IncomingMessage} req
 * @return {String}
 * @api private
 */

function defaultValue (req) {
  return (req.body && req.body._csrf) ||
    (req.query && req.query._csrf) ||
    (req.headers['csrf-token']) ||
    (req.headers['xsrf-token']) ||
    (req.headers['x-csrf-token']) ||
    (req.headers['x-xsrf-token'])
}

/**
 * Get a lookup of ignored methods.
 *
 * @param {array} methods
 * @returns {object}
 * @api private
 */

function getIgnoredMethods (methods) {
  var obj = Object.create(null)

  for (var i = 0; i < methods.length; i++) {
    var method = methods[i].toUpperCase()
    obj[method] = true
  }

  return obj
}

/**
 * Get the token secret from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @api private
 */

function getSecret (req, sessionKey) {
  // get the bag & key
  var bag = getSecretBag(req, sessionKey)
  var key = 'csrfSecret'

  if (!bag) {
    throw new Error('misconfigured csrf')
  }

  // return secret from bag
  return bag[key]
}

/**
 * Get the token secret bag from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @api private
 */

function getSecretBag (req, sessionKey) {
  // get secret from session
  return req[sessionKey]
}

/**
 * Set the token secret on the request.
 *
 * @param {IncomingMessage} req
 * @param {OutgoingMessage} res
 * @param {string} sessionKey
 * @param {string} val
 * @api private
 */

function setSecret (req, res, sessionKey, val) {
  // set secret on session
  req[sessionKey].csrfSecret = val
}

/**
 * Verify the configuration against the request.
 * @private
 */

function verifyConfiguration (req, sessionKey) {
  if (!getSecretBag(req, sessionKey)) {
    return false
  }

  return true
}
