// 解 beian.miit.gov.cn 的 JSL 挑战，抓取前端 JS，搜索 refresh 用法
const vm = require('vm');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36';

async function get(url, cookie) {
  const r = await fetch(url, {
    headers: { 'user-agent': UA, 'accept': 'text/html,application/xhtml+xml,*/*', 'cookie': cookie || '' },
    redirect: 'manual',
  });
  return { status: r.status, text: await r.text(), headers: Object.fromEntries(r.headers) };
}

function extractCookie(scriptText) {
  const ctx = {
    document: { cookie: '' },
    location: { pathname: '/', search: '', href: 'https://beian.miit.gov.cn/', reload() {} },
  };
  vm.createContext(ctx);
  try {
    vm.runInContext(scriptText, ctx);
  } catch (e) {
    console.log('eval err:', e.message);
  }
  return ctx.document.cookie;
}

async function main() {
  let res = await get('https://beian.miit.gov.cn/');
  let cookie = '';
  for (let i = 1; i <= 6 && res.status === 521; i++) {
    console.log(`STEP${i} status:`, res.status);
    const m = res.text.match(/<script>([\s\S]*?)<\/script>/);
    if (!m) { console.log('无挑战脚本'); break; }
    const c = extractCookie(m[1]);
    console.log(`STEP${i} cookie:`, c.slice(0, 60));
    if (!c) { console.log('未解出 cookie'); break; }
    cookie = c.split(';')[0] + '; ';
    res = await get('https://beian.miit.gov.cn/', cookie);
  }
  console.log('\nFINAL status:', res.status);
  const body = res.text;
  console.log('FINAL head:', body.slice(0, 300));

  const srcs = [...body.matchAll(/<script[^>]*src=["']([^"']+)["']/g)].map(x => x[1]);
  console.log('script srcs:', srcs);
  for (const src of srcs.slice(0, 20)) {
    const url = src.startsWith('http') ? src : 'https://beian.miit.gov.cn' + src;
    try {
      const r = await fetch(url, { headers: { 'user-agent': UA, 'cookie': cookie } });
      const t = await r.text();
      console.log(`\n=== ${url} (${r.status}, ${t.length}B) ===`);
      const hits = t.match(/refresh[^,;]{0,120}/gi);
      if (hits) {
        console.log('refresh hits:', hits.slice(0, 20));
      } else {
        console.log('(无 refresh 关键字)');
      }
    } catch (e) {
      console.log('fetch err', url, e.message);
    }
  }
}

main().catch(e => console.log('FATAL', e));
