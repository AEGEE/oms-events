const httprequest = require('request');
const restify = require('restify');

const config = require('./config/config.js');
const log = require('./config/logger.js');
const Event = require('./models/Event');
const UserCache = require('./models/UserCache');
const helpers = require('./helpers.js');
const user = require('./user.js');

exports.authenticateUser = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) {
    log.info('Unauthenticated request', req);
    return next(new restify.ForbiddenError({
      body: {
        success: false,
        message: 'No auth token provided',
      },
    }));
  }

  return UserCache.findOne({ token }, (userCacheErr, userCacheRes) => {
    // If not found, query core
    if (userCacheErr || !userCacheRes) {
      const opts = {
        url: `${config.core.url}:${config.core.port}/api/tokens/user`,
        method: 'POST',
        headers: {"x-auth-token": token},
        json: true,
        body: {token: token},
      };

      httprequest(opts, (requestError, requestResult, body) => {
        if (requestError) {
          log.error('Could not contact core to authenticate user', requestError);
          return next(new restify.InternalError({
            body: {
              success: false,
              message: requestError.message,
            },
          }));
        }

        if (!body.success) {
          log.info('Access denied to user', body);
          return next(new restify.UnauthorizedError({
            body: {
              success: false,
              message: 'Access denied',
            },
          }));
        }

        req.user = user.transformUser(body.data);

        // After calling next, try saving the fetched data to db
        if (config.enable_user_caching) {
          UserCache.find({ foreign_id: req.user.id }).remove(() => {
            const saveUserData = new UserCache();
            saveUserData.token = token;
            saveUserData.user = req.user;
            saveUserData.foreign_id = req.user.id;
            saveUserData.save((saveErr) => {
              if (saveErr) {
                log.warn('Could not store user data in cache', saveErr);
              }
            });
          });
        }

        return next();
      });
    } else {
      // If found in cache, use that one
      req.user = userCacheRes.user;
      return next();
    }
  });
};

exports.fetchSingleEvent = (req, res, next) => {
  if (!req.params.event_id) {
    log.info(req.params);
    return next(new restify.NotFoundError('No Event-id provided'));
  }

  // Checking if the passed ID is ObjectID or not.
  // We don't use ObjectID.isValid method, since it's not always
  // working properly, see http://stackoverflow.com/a/29231016/1206421
  let findObject;
  if (req.params.event_id.match(/^[0-9a-fA-F]{24}$/)) { // if it's indeed an ObjectID
    findObject = { _id: req.params.event_id };
  } else {
    findObject = { url: req.params.event_id };
  }

  return Event
    .findOne(findObject)
    .populate('status')
    .populate('organizers.roles')
    .populate('organizers.cached')
    .exec((err, event) => {
      if (err) {
        log.info(err);
        return next(new restify.InternalError({
          body: {
            success: false,
            message: err.message,
          },
        }));
      }

      if (event === null) {
        return next(new restify.NotFoundError({
          body: {
            success: false,
            message: `Event with id ${req.params.event_id} not found`,
          },
        }));
      }

      req.event = event;
      return next();
    });
};

// Middleware to check which permissions the user has, in regart to the current
// event if there is one Requires the fetchSingleEvent and fetchUserDetails
// middleware to be executed beforehand
exports.checkPermissions = (req, res, next) => {
  const permissions = {
    is: {},
    can: {},
  };

  permissions.is.superadmin = req.user.is_superadmin;

  // If user details are available, fill additional roles

  // TODO check if this is the right way to determine board positions
  permissions.is.boardmember = req.user.circles.find((circle) => {
    return circle.parent_id == config.global_board_circle;
  });

  permissions.can.view_local_involved_events = permissions.is.boardmember ||
    permissions.is.superadmin;

  const event_permissions = helpers.getEventPermissions(req.event, req.user);

  // Convert all to boolean and assign
  req.user.permissions = { is: {}, can: {} };
  for (const attr in permissions.is) {
    req.user.permissions.is[attr] = Boolean(permissions.is[attr]);
  }
  for (const attr in permissions.can) {
    req.user.permissions.can[attr] = Boolean(permissions.can[attr]);
  }
  for (const attr in event_permissions.is) {
    req.user.permissions.is[attr] = Boolean(event_permissions.is[attr]);
  }
  for (const attr in event_permissions.can) {
    req.user.permissions.can[attr] = Boolean(event_permissions.can[attr]);
  }
  if (event_permissions.special) {
    Array.prototype.push.apply(req.user.special, event_permissions.special);
  }

  // Filter out links
  if (req.event) {
    const intersects = (array1, array2) => array1.filter(elt => array2.includes(elt)).length > 0;
    req.event.links = req.event.links.filter((link) => {
      return link.visibility.users.includes(req.user.id.toString())
        || intersects(link.visibility.roles, []) // TODO replace when core permission system was implemented
        || intersects(link.visibility.special, req.user.special);
    });
  }

  return next();
};
