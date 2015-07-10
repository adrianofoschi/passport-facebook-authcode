var util = require('util');
var uri = require('url');
var crypto = require('crypto');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;

util.inherits(FacebookAuthCodeStrategy, OAuth2Strategy);

/**
 * `FacebookAuthCodeStrategy` constructor.
 *
 * The Facebook authentication strategy authenticates requests by delegating to
 * Facebook using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `error` should be set.
 *
 * Options:
 *   - `clientID`      your Facebook application's App ID
 *   - `clientSecret`  your Facebook application's App Secret
 *
 * Examples:
 *
 *     passport.use(new FacebookAuthCodeStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function FacebookAuthCodeStrategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://www.facebook.com/v2.2/dialog/oauth';
  options.tokenURL = options.tokenURL || 'https://graph.facebook.com/oauth/access_token';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);

  this.name = 'facebook-authcode';
  this._authCodeField = options.authCodeField || 'code';
  this._redirectUriField = options.redirectUriField || 'redirectUri';
  this._passReqToCallback = options.passReqToCallback;
  this._profileURL = options.profileURL || 'https://graph.facebook.com/v2.2/me';
  this._clientSecret = options.clientSecret;
  this._enableProof = options.enableProof;
  this._profileFields = options.profileFields || null;
  this._oauth2._useAuthorizationHeaderForGET = false;
}

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
FacebookAuthCodeStrategy.prototype.authenticate = function(req, options) {
  var self = this;
  authCode = (req.body && req.body[self._authCodeField]) || (req.query && req.query[self._authCodeField]) || (req.headers && req.headers[self._accessTokenField]),
  redirectUri = (req.body && req.body[self._redirectUriField]) || (req.query && req.query[self._redirectUriField]) || (req.headers && req.headers[self._refreshTokenField]);

  if (!authCode) {
    return this.fail({
      message: 'You should provide auth code'
    });
  }

  self._exchangeAuthCode(authCode, redirectUri, function(error, accessToken, refreshToken, resultsJson) {
    if (error) return self.fail(error);

    self._loadUserProfile(accessToken, function(error, profile) {
      if (error) return self.fail(error);

      function verified(error, user, info) {
        if (error) return self.error(error);
        if (!user) return self.fail(info);

        return self.success(user, info);
      }

      if (self._passReqToCallback) {
        self._verify(req, accessToken, refreshToken, profile, verified);
      } else {
        self._verify(accessToken, refreshToken, profile, verified);
      }
    });
  });
};


/**
 * Exchange authorization code for tokens
 *
 * @param {String} authCode
 * @param {Function} done
 * @api private
 */
FacebookAuthCodeStrategy.prototype._exchangeAuthCode = function(authCode, redirectUri, done) {
  var params = {
    'grant_type': 'authorization_code',
    'redirect_uri': redirectUri
  };
  this._oauth2.getOAuthAccessToken(authCode, params, done);
}


/**
 * Return extra Facebook-specific parameters to be included in the authorization
 * request.
 *
 * Options:
 *  - `display`  Display mode to render dialog, { `page`, `popup`, `touch` }.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
FacebookAuthCodeStrategy.prototype.authorizationParams = function(options) {
  return options.display ? {
    display: options.display
  } : {};
};

/**
 * Retrieve user profile from Facebook.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `facebook`
 *   - `id`               the user's Facebook ID
 *   - `username`         the user's Facebook username
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *   - `name.middleName`  the user's middle name
 *   - `gender`           the user's gender: `male` or `female`
 *   - `profileUrl`       the URL of the profile for the user on Facebook
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
FacebookAuthCodeStrategy.prototype.userProfile = function(accessToken, done) {
  var url = uri.parse(this._profileURL);

  if (this._enableProof) {
    // For further details, refer to https://developers.facebook.com/docs/reference/api/securing-graph-api/
    var proof = crypto.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
    url.search = (url.search ? url.search + '&' : '') + 'appsecret_proof=' + encodeURIComponent(proof);
  }

  url = uri.format(url);

  this._oauth2.get(url, accessToken, function(error, body, res) {
    if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

    try {
      var json = JSON.parse(body),
        profile = {
          provider: 'facebook',
          id: json.id,
          displayName: json.name || '',
          name: {
            familyName: json.last_name || '',
            givenName: json.first_name || '',
            middleName: json.middle_name || ''
          },
          gender: json.gender || '',
          locale: json.locale || '',
          emails: [{
            value: json.email || ''
          }],
          photos: [{
            value: ['https://graph.facebook.com/', json.id, '/picture?type=large'].join('') || ''
          }],
          _raw: body,
          _json: json
        };

      done(null, profile);
    } catch (e) {
      done(e);
    }
  });
};

/**
 * Expose `FacebookAuthCodeStrategy`.
 */
module.exports = FacebookAuthCodeStrategy;
module.exports.Strategy = FacebookAuthCodeStrategy;
