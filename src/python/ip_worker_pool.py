"""
多IP并行查询引擎 - IP Worker Pool
每个IP独立维护Token和查询管线，N个IP同时工作
"""
import asyncio, time, hashlib, uuid, ujson, logging
from collections import defaultdict

logger = logging.getLogger(__name__)

class IPWorkerPool:
    """
    多IP并行查询池
    - 每个IP独立获取Token
    - 每个IP维护自己的captcha计数
    - 403/限流时自动切换IP
    - 多个IP同时查询，最大化吞吐
    """
    
    def __init__(self, icp_instance, num_workers=10, captcha_per_token=200, queries_per_ip=3):
        """
        Args:
            icp_instance: beian实例（共享IPv6地址列表和连接池）
            num_workers: 并行工作的IP数量
            captcha_per_token: 每个Token最大打码次数
            queries_per_ip: 每个IP的并发查询数
        """
        self.icp = icp_instance
        self.num_workers = num_workers
        self.captcha_per_token = captcha_per_token
        self.queries_per_ip = queries_per_ip
        
        # IP状态管理: ip → state dict
        self._ip_states = {}  # ip → {token, expire, captcha_count, consecutive_fails, force_refresh}
        self._ip_locks = defaultdict(asyncio.Lock)  # 每个IP独立的锁
        self._ip_cooldown = {}  # IP冷却时间 (被限流后暂时不用)
        self._cooldown_seconds = 30  # 冷却30秒
        
        # 结果收集
        self.results = []
        self.stats = {'success': 0, 'failed': 0, 'errors': defaultdict(int)}
        self._stats_lock = asyncio.Lock()
        
        # 当前活跃IP集合
        self._active_ips = set()
        self._active_ips_lock = asyncio.Lock()
    
    def _pick_available_ip(self):
        """从IPv6池中选择一个可用的IP（未被冷却、未被封禁）"""
        addresses = self.icp.local_ipv6_addresses
        if not addresses:
            return None
        
        now = time.time()
        for _ in range(len(addresses)):
            # 使用icp的轮询机制
            ip = None
            for addr in addresses:
                # 跳过冷却中的IP
                if addr in self._ip_cooldown:
                    if now - self._ip_cooldown[addr] < self._cooldown_seconds:
                        continue
                    else:
                        del self._ip_cooldown[addr]  # 冷却到期
                # 跳过被封禁的IP
                if addr in self.icp._blocked_ip_cache:
                    continue
                # 跳过不可达IP
                if addr in self.icp._unreachable_ip_cache:
                    ts = self.icp._unreachable_ip_cache[addr]
                    if now - ts < 600:
                        continue
                ip = addr
                break
            
            if ip:
                return ip
            
            # 如果没有可用IP，放宽冷却限制
            if self._ip_cooldown:
                oldest_ip = min(self._ip_cooldown, key=self._ip_cooldown.get)
                if now - self._ip_cooldown[oldest_ip] > 5:  # 至少等5秒
                    del self._ip_cooldown[oldest_ip]
                    return oldest_ip
        
        return addresses[0] if addresses else None
    
    def _mark_ip_rate_limited(self, ip):
        """标记IP被限流，进入冷却"""
        self._ip_cooldown[ip] = time.time()
        # 清理该IP的token状态
        if ip in self._ip_states:
            del self._ip_states[ip]
        logger.warning(f"⏳ IP {ip[-20:]} 进入冷却 {self._cooldown_seconds}s")
    
    async def _get_token_for_ip(self, ip):
        """为指定IP获取Token（带缓存）"""
        # 检查缓存
        if ip in self._ip_states:
            state = self._ip_states[ip]
            if (not state.get('force_refresh') 
                and state.get('captcha_count', 0) < self.captcha_per_token
                and state.get('expire', 0) > int(time.time() * 1000)):
                return True, state['token']
        
        # 需要获取/刷新Token
        async with self._ip_locks[ip]:
            # 双重检查
            if ip in self._ip_states:
                state = self._ip_states[ip]
                if (not state.get('force_refresh') 
                    and state.get('captcha_count', 0) < self.captcha_per_token
                    and state.get('expire', 0) > int(time.time() * 1000)):
                    return True, state['token']
            
            # 确实需要获取新Token
            timeStamp = round(time.time() * 1000)
            authSecret = "testtest" + str(timeStamp)
            authKey = hashlib.md5(authSecret.encode(encoding="UTF-8")).hexdigest()
            auth_data = {"authKey": authKey, "timeStamp": timeStamp}
            
            base_header = {
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "Origin": "https://beian.miit.gov.cn",
                "Referer": "https://beian.miit.gov.cn/",
                "Cookie": f"__jsluid_s={uuid.uuid4().hex}",
            }
            
            try:
                async with self.icp.get_session(ipv6=ip) as session:
                    async with session.post(
                        self.icp.url, data=auth_data, headers=base_header
                    ) as req:
                        req_text = await req.text()
                        
                        if "当前访问疑似黑客攻击" in req_text:
                            logger.warning(f"IP {ip[-20:]} 被创宇盾拦截")
                            self._mark_ip_rate_limited(ip)
                            return False, "创宇盾拦截"
                        
                        t = ujson.loads(req_text)
                        token = t["params"]["bussiness"]
                        expire = int(time.time() * 1000) + t["params"]["expire"]
                        
                        self._ip_states[ip] = {
                            'token': token,
                            'expire': expire,
                            'captcha_count': 0,
                            'consecutive_fails': 0,
                            'force_refresh': False,
                        }
                        logger.info(f"🔑 IP {ip[-20:]} 获取新Token (过期: {expire/1000:.0f}s)")
                        return True, token
            except BaseException as e:
                logger.warning(f"IP {ip[-20:]} 获取Token失败: {e}")
                self._mark_ip_rate_limited(ip)
                return False, str(e)
    
    async def _do_captcha(self, ip, token):
        """为指定IP+Token完成一次验证码"""
        state = self._ip_states.get(ip)
        if not state:
            return False, "无Token状态", '', '', ''
        
        base_header = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://beian.miit.gov.cn",
            "Referer": "https://beian.miit.gov.cn/",
            "Cookie": f"__jsluid_s={uuid.uuid4().hex}",
            "token": token,
        }
        
        try:
            # Step 1: 获取验证码图片
            data = self.icp.get_clientUid()
            length = str(len(str(data).encode("utf-8")))
            base_header["Content-Length"] = length
            
            async with self.icp.get_session(ipv6=ip) as session:
                async with session.post(
                    self.icp.getCheckImage, data=data, headers=base_header
                ) as req:
                    res = await req.json()
            
            p_uuid = res["params"]["uuid"]
            big_image = res["params"]["bigImage"]
            small_image = res["params"]["smallImage"]
            
            # Step 2: OCR滑块匹配
            match_success, offset_x = self.icp.match_slider_offset(small_image, big_image)
            if not match_success:
                state['consecutive_fails'] += 1
                if state['consecutive_fails'] >= 2:
                    state['force_refresh'] = True
                return False, "滑块匹配失败", '', '', ''
            
            # Step 3: 提交验证码
            check_data = ujson.dumps({"key": p_uuid, "value": str(offset_x)})
            length = str(len(check_data.encode("utf-8")))
            base_header["Content-Length"] = length
            
            async with self.icp.get_session(ipv6=ip) as session:
                async with session.post(
                    self.icp.checkImage, data=check_data, headers=base_header
                ) as req:
                    check_res = await req.text()
            
            check_result = ujson.loads(check_res)
            if not check_result.get("success", False):
                state['consecutive_fails'] += 1
                if state['consecutive_fails'] >= 2:
                    state['force_refresh'] = True
                return False, "验证码识别失败", '', '', ''
            
            # 成功
            state['captcha_count'] += 1
            state['consecutive_fails'] = 0
            sign = check_result["params"]
            
            return True, p_uuid, token, sign, base_header
            
        except BaseException as e:
            err_msg = str(e)
            if '403' in err_msg or 'unexpected mimetype' in err_msg.lower():
                # 被限流
                logger.warning(f"IP {ip[-20:]} captcha 403限流")
                self._mark_ip_rate_limited(ip)
            state['consecutive_fails'] += 1
            if state['consecutive_fails'] >= 2:
                state['force_refresh'] = True
            return False, err_msg[:80], '', '', ''
    
    async def _query_domain(self, ip, domain_name):
        """在指定IP上查询单个域名"""
        max_retries = 3
        for attempt in range(max_retries):
            # 1. 确保有Token
            token_ok, token = await self._get_token_for_ip(ip)
            if not token_ok:
                ip = self._pick_available_ip()
                if not ip:
                    return (domain_name, False, "无可用IP")
                continue
            
            # 2. 验证码
            captcha_ok, p_uuid, token, sign, base_header = await self._do_captcha(ip, token)
            if not captcha_ok:
                err = str(p_uuid)[:50]
                if '403' in err or '限流' in err or 'unexpected mimetype' in err.lower():
                    ip = self._pick_available_ip()
                    if not ip:
                        return (domain_name, False, "所有IP被限流")
                    continue
                # 其他验证码失败，重试
                continue
            
            # 3. 查询
            info = ujson.loads(self.icp.typj.get(0))
            info["pageNum"] = 1
            info["pageSize"] = 26
            info["unitName"] = domain_name
            
            length = str(len(str(ujson.dumps(info, ensure_ascii=False)).encode("utf-8")))
            base_header.update({
                "Content-Length": length,
                "uuid": p_uuid,
                "token": token,
                "sign": sign
            })
            
            try:
                async with self.icp.get_session(ipv6=ip) as session:
                    async with session.post(
                        self.icp.queryByCondition,
                        data=ujson.dumps(info, ensure_ascii=False),
                        headers=base_header
                    ) as req:
                        res = await req.text()
                
                result = ujson.loads(res)
                if result.get("success"):
                    items = result.get("params", {}).get("list", [])
                    return (domain_name, True, items)
                else:
                    # 查询失败可能是token问题
                    state = self._ip_states.get(ip, {})
                    state['force_refresh'] = True
                    continue
                    
            except BaseException as e:
                logger.debug(f"查询{domain_name}失败: {e}")
                continue
        
        return (domain_name, False, f"重试{max_retries}次后失败")
    
    async def _worker(self, worker_id, domain_queue, result_queue, ip_sem):
        """Worker协程：持续从队列取域名查询"""
        while True:
            try:
                domain_name = domain_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            
            async with ip_sem:
                # 选择IP
                ip = self._pick_available_ip()
                if not ip:
                    logger.error(f"Worker {worker_id}: 无可用IP")
                    await result_queue.put((domain_name, False, "无可用IP"))
                    continue
                
                # 查询
                name, ok, data = await self._query_domain(ip, domain_name)
                await result_queue.put((name, ok, data))
                
                # 更新统计
                async with self._stats_lock:
                    if ok:
                        self.stats['success'] += 1
                    else:
                        self.stats['failed'] += 1
                        err_key = str(data)[:30] if isinstance(data, str) else 'unknown'
                        self.stats['errors'][err_key] += 1
            
            domain_queue.task_done()
    
    async def run_batch(self, domains, progress_callback=None):
        """
        运行批量查询
        
        Args:
            domains: 域名列表
            progress_callback: 进度回调 async def callback(completed, total, stats)
        
        Returns:
            (results, stats)
        """
        domain_queue = asyncio.Queue()
        result_queue = asyncio.Queue()
        
        for d in domains:
            await domain_queue.put(d)
        
        total = len(domains)
        ip_sem = asyncio.Semaphore(self.queries_per_ip * self.num_workers)
        
        # 启动workers
        workers = []
        for i in range(self.num_workers):
            w = asyncio.create_task(
                self._worker(i, domain_queue, result_queue, ip_sem)
            )
            workers.append(w)
        
        # 收集结果，支持进度回调
        results = []
        completed = 0
        t_start = time.time()
        
        while completed < total:
            try:
                result = await asyncio.wait_for(result_queue.get(), timeout=5.0)
                results.append(result)
                completed += 1
                
                if progress_callback:
                    elapsed = time.time() - t_start
                    qps = completed / elapsed if elapsed > 0 else 0
                    await progress_callback(completed, total, {
                        'elapsed': elapsed,
                        'qps': qps,
                        'qph': qps * 3600,
                        'success': self.stats['success'],
                        'failed': self.stats['failed'],
                        'active_ips': len(self._ip_states),
                        'cooldown_ips': len(self._ip_cooldown),
                    })
            except asyncio.TimeoutError:
                # 检查workers是否都完成了
                all_done = all(w.done() for w in workers)
                if all_done:
                    break
        
        # 等待所有workers完成
        await asyncio.gather(*workers, return_exceptions=True)
        
        # 收集剩余结果
        while not result_queue.empty():
            try:
                result = result_queue.get_nowait()
                results.append(result)
            except asyncio.QueueEmpty:
                break
        
        return results, dict(self.stats)
