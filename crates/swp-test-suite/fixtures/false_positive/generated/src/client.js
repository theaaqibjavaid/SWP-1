'use strict';

// What an OpenAPI generator emits. §27 names "generated code" deliberately: a
// generator produces the same twenty statement shapes with a different name in
// each, which is the most self-similar source a scanner can meet. Any bound on
// coincidence that cannot survive this file is not worth printing.

const BASE = 'https://api.example.com/v1';
const USER_AGENT = 'example-sdk/2.1.0';
const DEFAULT_TIMEOUT = 30000;
const MAX_RETRIES = 3;

function request(client, method, path, body, query) {
  const url = new URL(path, client.base);
  for (const key of Object.keys(query || {})) {
    url.searchParams.set(key, String(query[key]));
  }
  return client.transport({
    url: url.toString(),
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: {
      'user-agent': USER_AGENT,
      accept: 'application/json',
      'content-type': 'application/json',
      authorization: 'Bearer ' + client.token,
    },
    timeout: client.timeout || DEFAULT_TIMEOUT,
  });
}

class ProjectsApi {
  constructor(client) {
    this.client = client;
  }
  listProjects(params) {
    return request(this.client, 'GET', '/projects', undefined, params);
  }
  createProject(body) {
    return request(this.client, 'POST', '/projects', body, undefined);
  }
  getProject(projectId) {
    return request(this.client, 'GET', '/projects/' + encodeURIComponent(projectId), undefined, undefined);
  }
  updateProject(projectId, body) {
    return request(this.client, 'PATCH', '/projects/' + encodeURIComponent(projectId), body, undefined);
  }
  deleteProject(projectId) {
    return request(this.client, 'DELETE', '/projects/' + encodeURIComponent(projectId), undefined, undefined);
  }
}

class DeploymentsApi {
  constructor(client) {
    this.client = client;
  }
  listDeployments(params) {
    return request(this.client, 'GET', '/deployments', undefined, params);
  }
  createDeployment(body) {
    return request(this.client, 'POST', '/deployments', body, undefined);
  }
  getDeployment(deploymentId) {
    return request(this.client, 'GET', '/deployments/' + encodeURIComponent(deploymentId), undefined, undefined);
  }
  cancelDeployment(deploymentId) {
    return request(this.client, 'POST', '/deployments/' + encodeURIComponent(deploymentId) + '/cancel', {}, undefined);
  }
}

class EnvironmentsApi {
  constructor(client) {
    this.client = client;
  }
  listEnvironments(params) {
    return request(this.client, 'GET', '/environments', undefined, params);
  }
  createEnvironment(body) {
    return request(this.client, 'POST', '/environments', body, undefined);
  }
  getEnvironment(environmentId) {
    return request(this.client, 'GET', '/environments/' + encodeURIComponent(environmentId), undefined, undefined);
  }
  promoteEnvironment(environmentId, body) {
    return request(this.client, 'POST', '/environments/' + encodeURIComponent(environmentId) + '/promote', body, undefined);
  }
}

class Client {
  constructor(options) {
    this.base = options.base || BASE;
    this.token = options.token || '';
    this.transport = options.transport || fetch;
    this.timeout = options.timeout || DEFAULT_TIMEOUT;
    this.retries = options.retries === undefined ? MAX_RETRIES : options.retries;
    this.projects = new ProjectsApi(this);
    this.deployments = new DeploymentsApi(this);
    this.environments = new EnvironmentsApi(this);
  }
}

module.exports = { BASE, USER_AGENT, DEFAULT_TIMEOUT, MAX_RETRIES, Client, ProjectsApi, DeploymentsApi, EnvironmentsApi };
