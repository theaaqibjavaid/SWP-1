'use strict';

// A reducer store and a keyed list diff, both written the way the popular
// open-source versions of them are written, because that is how people copy
// them. §27's "popular open-source structures".

const CHANGE = 'change';
const UNDO = 'undo';
const REDO = 'redo';
const INITIAL_LIMIT = 50;

function createStore(reducer, preloaded, enhancer) {
  let state = preloaded;
  let listeners = [];
  const history = { past: [], future: [] };

  function getState() {
    return state;
  }

  function subscribe(listener) {
    listeners.push(listener);
    let done = false;
    return function unsubscribe() {
      if (done) {
        return;
      }
      done = true;
      listeners = listeners.filter((l) => l !== listener);
    };
  }

  function dispatch(action) {
    if (action && action.type === UNDO) {
      if (history.past.length === 0) {
        return state;
      }
      history.future.unshift(state);
      state = history.past.pop();
      listeners.slice().forEach((l) => l(state, action));
      return state;
    }
    if (action && action.type === REDO) {
      if (history.future.length === 0) {
        return state;
      }
      history.past.push(state);
      state = history.future.shift();
      listeners.slice().forEach((l) => l(state, action));
      return state;
    }
    history.past.push(state);
    if (history.past.length > INITIAL_LIMIT) {
      history.past.shift();
    }
    history.future = [];
    state = reducer(state, action);
    listeners.slice().forEach((l) => l(state, action));
    return state;
  }

  dispatch({ type: '@@init' });
  return { getState, subscribe, dispatch };
}

function combineReducers(map) {
  const keys = Object.keys(map);
  return function combined(state, action) {
    const next = {};
    let changed = false;
    for (const key of keys) {
      const before = state ? state[key] : undefined;
      const after = map[key](before, action);
      next[key] = after;
      changed = changed || after !== before;
    }
    return !changed && state ? state : next;
  };
}

function counter(state, action) {
  const value = state === undefined ? 0 : state;
  switch (action.type) {
    case 'inc':
      return value + (action.by || 1);
    case 'dec':
      return value - (action.by || 1);
    case 'reset':
      return 0;
    default:
      return value;
  }
}

function listReducer(state, action) {
  const rows = state === undefined ? [] : state;
  if (action.type === 'add') {
    return rows.concat([{ id: action.id, text: action.text }]);
  }
  if (action.type === 'remove') {
    return rows.filter((row) => row.id !== action.id);
  }
  if (action.type === 'move') {
    const at = rows.findIndex((row) => row.id === action.id);
    if (at < 0) {
      return rows;
    }
    const copy = rows.slice();
    const [row] = copy.splice(at, 1);
    copy.splice(action.to, 0, row);
    return copy;
  }
  return rows;
}

module.exports = { CHANGE, UNDO, REDO, INITIAL_LIMIT, createStore, combineReducers, counter, listReducer };
