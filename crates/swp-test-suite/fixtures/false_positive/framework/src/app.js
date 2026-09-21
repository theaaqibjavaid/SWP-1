'use strict';

// A middleware chain in the shape a hundred tutorials draw it: an app object, a
// use(), a router, an error handler, a JSON body reader with a size limit.
//
// §27's "common framework patterns" and "common boilerplate" case. The
// structures here are the ones copied most often, and every constant in the
// file is a default someone read off a documentation page.

const DEFAULT_PORT = 3000;
const MAX_BODY = 1024 * 100;
const STATUS = {
  ok: 200,
  created: 201,
  noContent: 204,
  badRequest: 400,
  unauthorized: 401,
  forbidden: 403,
  notFound: 404,
  conflict: 409,
  tooMany: 429,
  serverError: 500,
};

function createApp() {
  const stack = [];
  const onError = [];
  return {
    use(handler) {
      stack.push(handler);
      return this;
    },
    fail(handler) {
      onError.push(handler);
      return this;
    },
    handle(req, res, next) {
      let index = 0;
      const dispatch = (err) => {
        if (err) {
          for (const handler of onError) {
            handler(err, req, res);
          }
          return;
        }
        if (index >= stack.length) {
          if (next) {
            next();
          } else {
            res.status(STATUS.notFound).send({ error: 'not found' });
          }
          return;
        }
        const handler = stack[index++];
        try {
          handler(req, res, dispatch);
        } catch (problem) {
          dispatch(problem);
        }
      };
      dispatch(null);
    },
  };
}

function jsonBody(options) {
  const limit = (options && options.limit) || MAX_BODY;
  return function readBody(req, res, next) {
    let text = '';
    req.on('data', (chunk) => {
      text += chunk;
      if (text.length > limit) {
        res.status(413).send({ error: 'payload too large' });
        text = '';
      }
    });
    req.on('end', () => {
      if (!text) {
        req.body = {};
        return next();
      }
      try {
        req.body = JSON.parse(text);
        next();
      } catch (err) {
        next(new SyntaxError('invalid JSON body'));
      }
    });
  };
}

function requestId() {
  let counter = 0;
  return function withId(req, res, next) {
    counter = (counter + 1) % 100000;
    req.id = counter.toString(16).padStart(4, '0');
    req.at = Date.now();
    next();
  };
}

function asyncHandler(fn) {
  return function wrapped(req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function cors(options)
{
  const origin = (options && options.origin) || '*';
  const methods = (options && options.methods) || 'GET,POST,PUT,PATCH,DELETE';
  return function withCors(req, res, next) {
    res.setHeader('access-control-allow-origin', origin);
    res.setHeader('access-control-allow-methods', methods);
    res.setHeader('access-control-allow-headers', 'content-type,authorization');
    if (req.method === 'OPTIONS') {
      return res.status(STATUS.noContent).send('');
    }
    next();
  };
}

module.exports = { DEFAULT_PORT, MAX_BODY, STATUS, createApp, jsonBody, requestId, asyncHandler, cors };
