"""
Token预取池 + 隔离并发查询引擎
- 启动时在N个IP上预取Token
- 每个查询使用独立QueryContext，不共享状态
- 支持真正的conc=N内部并发
"""
import asyncio, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ymicp import beian, QueryContext

class TokenPool:
    """Token预取池：在多个IP上预先获取Token，消除auth端点拥塞"""
    
    def __init__(self, icp_instance, num_ips=20, max_captcha_per_token=200, stagger_ms=200):
        """
        Args:
            icp_instance: beian实例（共享连接池和IP列表）
            num_ips: 预取Token的IP数量
            max_captcha_per_token: 每个Token最大使用次数
            stagger_ms: IP间错开启动间隔（避免同时auth导致拥塞）
        """
        self.icp = icp_instance
        self.num_ips = num_ips
        self.max_captcha = max_captcha_per_token
        self.stagger_ms = stagger_ms
        
        # IP → QueryContext 映射
        self._contexts: dict[str, QueryContext] = {}
        self._available_ips = asyncio.Queue()
        self._ready = False
        self._total_prefetched = 0
        self._prefetch_errors = 0
    
    async def initialize(self):
        """预取Token：在N个IP上错开获取Token"""
        addresses = self.icp.local_ipv6_addresses
        if not addresses:
            raise RuntimeError("无可用IPv6地址")
        
        actual = min(self.num_ips, len(addresses))
        logger = __import__('logging').getLogger(__name__)
        logger.info(f"🔧 TokenPool: 预取 {actual} 个IP的Token...")
        
        t0 = time.time()
        tasks = []
        for i in range(actual):
            ip = addresses[i * (len(addresses) // actual)] if actual > 1 else addresses[0]
            # 错开启动：每个IP间隔stagger_ms
            delay = i * self.stagger_ms / 1000
            tasks.append(self._prefetch_one(ip, i, delay))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for r in results:
            if isinstance(r, Exception):
                self._prefetch_errors += 1
                logger.error(f"预取失败: {r}")
            elif r:
                self._total_prefetched += 1
        
        elapsed = time.time() - t0
        logger.info(f"✅ TokenPool就绪: {self._total_prefetched}/{actual} IPs, "
                   f"{elapsed:.1f}s, 错误:{self._prefetch_errors}")
        
        self._ready = True
        return self._total_prefetched
    
    async def _prefetch_one(self, ip, idx, delay):
        """在单个IP上预取Token"""
        logger = __import__('logging').getLogger(__name__)
        if delay > 0:
            await asyncio.sleep(delay)
        
        ctx = QueryContext(ip, max_captcha_per_token=self.max_captcha)
        
        try:
            # 获取Token
            success, token, _ = await self.icp.get_token(ipv6=ip, ctx=ctx)
            if not success:
                logger.warning(f"预取[{idx}] IP={ip[-20:]} Token失败: {token}")
                return False
            
            # 完成一次验证码（预热Token+验证码流程）
            success, p_uuid, _, sign, _ = await self.icp.check_img(ipv6=ip, ctx=ctx)
            if not success:
                logger.warning(f"预取[{idx}] IP={ip[-20:]} 验证码失败: {p_uuid}")
                # Token有效但验证码失败，仍可加入池（下次使用时重新验证码）
            
            self._contexts[ip] = ctx
            await self._available_ips.put(ip)
            logger.info(f"✅ 预取[{idx}] IP={ip[-20:]} Token就绪")
            return True
        except Exception as e:
            logger.error(f"预取[{idx}] IP={ip[-20:]} 异常: {e}")
            return False
    
    async def get_context(self):
        """获取一个可用IP的QueryContext（阻塞直到有可用）"""
        ip = await self._available_ips.get()
        ctx = self._contexts.get(ip)
        return ip, ctx
    
    async def return_context(self, ip, ctx):
        """归还IP到可用池"""
        await self._available_ips.put(ip)
    
    async def mark_ip_blocked(self, ip):
        """标记IP不可用（被限流/封禁），从池中移除并获取新IP"""
        logger = __import__('logging').getLogger(__name__)
        if ip in self._contexts:
            del self._contexts[ip]
            logger.warning(f"🚫 TokenPool: IP {ip[-20:]} 移除")
        
        # 尝试补充一个新IP
        addresses = self.icp.local_ipv6_addresses
        for addr in addresses:
            if addr not in self._contexts and addr not in self.icp._blocked_ip_cache:
                ctx = QueryContext(addr, max_captcha_per_token=self.max_captcha)
                success, token, _ = await self.icp.get_token(ipv6=addr, ctx=ctx)
                if success:
                    self._contexts[addr] = ctx
                    await self._available_ips.put(addr)
                    logger.info(f"🔄 TokenPool: 补充IP {addr[-20:]}")
                    return addr
        return None
    
    @property
    def available_count(self):
        return self._available_ips.qsize()
    
    @property
    def total_contexts(self):
        return len(self._contexts)


async def run_concurrent_batch(icp, pool, domains, conc_per_ip=3):
    """
    使用TokenPool + QueryContext进行并发批量查询
    每个查询使用独立ctx，真正的conc=N并发
    """
    total = len(domains)
    results = [None] * total
    stats = {'ok': 0, 'fail': 0}
    lock = asyncio.Lock()
    
    # 全局信号量限制总并发
    max_concurrent = pool.num_ips * conc_per_ip
    global_sem = asyncio.Semaphore(max_concurrent)
    
    async def query_with_context(idx, domain):
        async with global_sem:
            # 从池中获取一个可用IP+Context
            ip, ctx = await pool.get_context()
            try:
                ok, msg = await icp.getbeian(domain, 0, 1, 26, ctx=ctx)
            except Exception as e:
                ok = False
                msg = f"Exception: {str(e)[:80]}"
                
                async with lock:
                    if ok:
                        stats['ok'] += 1
                    else:
                        stats['fail'] += 1
                
                # 如果被限流（创宇盾），标记IP
                if not ok and '创宇盾' in str(msg):
                    await pool.mark_ip_blocked(ip)
                
                return (idx, domain, ok, str(msg)[:80])
            finally:
                await pool.return_context(ip, ctx)
    
    # 启动所有查询
    t_start = time.time()
    tasks = [query_with_context(i, d) for i, d in enumerate(domains)]
    
    # 分批收集结果
    for i in range(0, len(tasks), 50):
        batch = tasks[i:i+50]
        batch_results = await asyncio.gather(*batch, return_exceptions=True)
        for item in batch_results:
            if isinstance(item, Exception):
                logger = __import__('logging').getLogger(__name__)
                logger.error(f"查询异常: {item}")
                continue
            idx, domain, ok, msg = item
            results[idx] = (domain, ok, msg)
        
        elapsed = time.time() - t_start
        qps = stats['ok'] / elapsed if elapsed > 0 else 0
        done = min(i+50, total)
        print(f"  [{elapsed:.0f}s] {done}/{total} | 成功:{stats['ok']} | "
              f"{qps:.2f}q/s={qps*3600:.0f}q/h | 池可用:{pool.available_count}")
    
    elapsed = time.time() - t_start
    return results, stats, elapsed
