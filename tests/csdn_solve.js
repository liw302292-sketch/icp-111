// 解 CSDN 反爬脚本：宿主 eval + 假 document/location，捕获脚本副作用
const fs = require('fs');

const html = fs.readFileSync('tests/csdn_article.html', 'utf8');
const full = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
// 把最后的间接 eval 换成 记录po+直接eval（函数作用域内 oo 可见）
const patched = full.split('eval("qo=eval;qo(po);")').join('(globalThis.__po=po, eval(po))');
const fnName = (full.match(/function\s+(\w+)\s*\(/) || [])[1];
const patched2 = patched + `; globalThis.__fn = (typeof ${fnName} === "function") ? ${fnName} : null;`;

const writes = [];
globalThis.document = {
  cookie: '',
  write: (s) => writes.push(s),
  getElementById: () => null,
  createElement: () => ({ style: {}, appendChild() {}, setAttribute() {} }),
  getElementsByTagName: () => [],
};
globalThis.location = {
  href: 'https://m.blog.csdn.net/hermitcrabzoo/article/details/143599504',
  pathname: '/hermitcrabzoo/article/details/143599504',
  search: '',
  reload() { this._reloaded = true; },
};
globalThis.window = globalThis;
globalThis.navigator = { userAgent: 'Mozilla/5.0' };
globalThis.setTimeout = () => 0;
globalThis.clearTimeout = () => 0;

try {
  console.log('HEAD:', full.slice(0, 120));
  eval(patched2);
  console.log('LEN:', full.length);
  const m = full.match(/setTimeout\("(\w+)\((\d+)\)"/);
  console.log('FN:', fnName, 'defined:', typeof globalThis.__fn);
  if (m && typeof globalThis.__fn === 'function') {
    globalThis.__fn(+m[2]);
  }
} catch (e) {
  console.log('eval err:', e && e.message);
}
console.log('PO:', String(globalThis.__po || '').slice(0, 400));
console.log('cookie:', globalThis.document.cookie);
console.log('location.href:', globalThis.location.href);
console.log('reloaded:', globalThis.location._reloaded);
console.log('writes:', writes.slice(0, 3).map(w => w.slice(0, 600)));
