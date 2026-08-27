# -*- coding: utf-8 -*-
import sys, asyncio, hashlib, time
sys.path.insert(0, 'src/python')
from ymicp import get_local_ipv6_addresses
import aiohttp

async def auth(ip):
    ts = round(time.time()*1000)
    key = hashlib.md5(f'testtest{ts}'.encode()).hexdigest()
    h = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0.0.0 Safari/537.36',
         'Accept':'application/json, text/plain, */*','Origin':'https://beian.miit.gov.cn',
         'Referer':'https://beian.miit.gov.cn/','Content-Type':'application/x-www-form-urlencoded'}
    conn = aiohttp.TCPConnector(local_addr=(ip, 0))
    async with aiohttp.ClientSession(connector=conn) as s:
        try:
            async with s.post('https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth',
                              data={'authKey':key,'timeStamp':ts}, headers=h,
                              timeout=aiohttp.ClientTimeout(total=10)) as r:
                t = await r.text()
                return r.status, ('OK' if '"success":true' in t else t[:60])
        except Exception as e:
            return 'ERR', str(e)[:60]

async def main():
    home = [a for a in get_local_ipv6_addresses() if a.startswith('2409:8a1a')]
    for a in home[:5]:
        st, msg = await auth(a)
        print(a[-20:], '->', st, msg)
        await asyncio.sleep(1)

asyncio.run(main())
