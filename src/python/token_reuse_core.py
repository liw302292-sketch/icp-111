"""Token复用核心测试：1 IP, 1 Token, 200查询"""
import asyncio, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ymicp import beian, QueryContext

DOMAINS = [
    'baidu.com','qq.com','taobao.com','sina.com.cn','sohu.com',
    '163.com','126.com','sogou.com','360.cn','tmall.com',
    'jd.com','meituan.com','zhihu.com','bilibili.com','csdn.net',
    'cnblogs.com','douban.com','weibo.com','alipay.com','mi.com',
    'oppo.com','vivo.com','ele.me','qunar.com','ctrip.com',
    'icbc.com.cn','ccb.com','pingan.com','lianjia.com','anjuke.com',
    'fang.com','autohome.com.cn','bitauto.com','pcauto.com.cn','zol.com.cn',
    'ithome.com','chinaz.com','xiaomi.com','huawei.com','lenovo.com.cn',
    'dell.com','acer.com.cn','asus.com.cn','aliyun.com',
    'huaweicloud.com','smzdm.com','dianping.com','meishij.net','douguo.com',
    'huya.com','douyin.com','kuaishou.com','toutiao.com','ixigua.com',
    'hao123.com','2345.com','baike.com','tuniu.com','lvmama.com',
    'mafengwo.cn','huxiu.com','36kr.com','iheima.com','geekpark.net',
    'oneplus.com','smartisan.com','xiachufang.com','daydaycook.com',
    'youzan.com','weimob.com','beike.com','ziroom.com','xcar.com.cn',
    'dongchedi.com','pcpop.com','yesky.com','donews.com','admin5.com',
    'thinkpad.com','msi.com','gigabyte.cn','csc.com.cn','htsec.com',
    'gtja.com','gf.com.cn','ifanr.com','shopex.cn','ecshop.com',
    'hishop.com','im286.com','luosimao.com','mobvista.com','hp.com',
]
domains = (DOMAINS * 3)[:200]

async def main():
    icp = beian()
    if not icp.local_ipv6_addresses:
        print("NO IPv6")
        return
    
    ip = icp.local_ipv6_addresses[0]
    ctx = QueryContext(ip, max_captcha_per_token=200)
    
    print(f"IP: {ip[-20:]}")
    print(f"Token上限: {ctx.max_captcha_per_token}次")
    print(f"域名数: {len(domains)}")
    print()
    
    results = []
    ok_count = 0
    fail_count = 0
    token_refreshes = 0
    last_token_count = 0
    
    t_start = time.time()
    
    for i, domain in enumerate(domains):
        # 记录当前token状态
        before_count = ctx.captcha_count
        
        try:
            ok, msg = await icp.getbeian(domain, 0, 1, 26, ctx=ctx)
        except Exception as e:
            ok = False
            msg = str(e)[:80]
        
        after_count = ctx.captcha_count
        captcha_used_this_query = after_count - before_count
        
        # 检测token是否被刷新（captcha_count归零=新token）
        if after_count < before_count:
            token_refreshes += 1
        
        if ok:
            ok_count += 1
        else:
            fail_count += 1
        
        results.append({
            'domain': domain,
            'ok': ok,
            'captcha_used': captcha_used_this_query,
            'token_count': after_count,
            'msg': str(msg)[:60] if not ok else '',
        })
        
        elapsed = time.time() - t_start
        qps = (i+1) / elapsed if elapsed > 0 else 0
        
        # 每10个输出一行
        if (i+1) % 10 == 0 or i == 0:
            print(f"[{elapsed:.0f}s] {i+1:3d}/{len(domains)} | "
                  f"成功:{ok_count} 失败:{fail_count} | "
                  f"{qps:.2f}q/s={qps*3600:.0f}q/h | "
                  f"Token打码:{after_count}/{ctx.max_captcha_per_token} | "
                  f"刷新:{token_refreshes}次", flush=True)
    
    elapsed = time.time() - t_start
    qps = ok_count / elapsed if elapsed > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"📊 1 Token 复用结果")
    print(f"{'='*60}")
    print(f"总查询: {len(domains)}")
    print(f"成功: {ok_count} | 失败: {fail_count}")
    print(f"成功率: {ok_count/len(domains)*100:.1f}%")
    print(f"总耗时: {elapsed:.1f}s")
    print(f"吞吐: {qps:.2f} q/s = {qps*3600:.0f} q/h")
    print(f"Token刷新次数: {token_refreshes}")
    print(f"最终Token打码: {ctx.captcha_count}/{ctx.max_captcha_per_token}")
    print(f"Token复用: 1个Token服务了 {ctx.captcha_count} 次查询" if token_refreshes == 0 
          else f"Token复用: {token_refreshes+1}个Token服务了 {ok_count} 次查询, 平均{ok_count/(token_refreshes+1):.0f}次/Token")
    
    # 分析失败原因
    fail_msgs = {}
    for r in results:
        if not r['ok']:
            key = r['msg'][:40]
            fail_msgs[key] = fail_msgs.get(key, 0) + 1
    if fail_msgs:
        print(f"\n失败分布:")
        for msg, count in sorted(fail_msgs.items(), key=lambda x: -x[1])[:5]:
            print(f"  [{count:3d}] {msg}")

asyncio.run(main())
