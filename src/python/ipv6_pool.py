# -*- coding: utf-8 -*-
"""
IPv6地址池管理模块
负责IPv6地址的获取、验证、维护和轮询
"""
import asyncio
import random
import time
import socket
import os
import subprocess as sp
import aiohttp
from typing import List, Optional
from mlog import logger
from load_config import config
from utils import get_local_ipv6_addresses, get_manual_ipv6_addresses, configure_ipv6_addresses, is_public_ipv6, check_has_permanent_ipv6


class IPv6AddressPool:
    """IPv6地址池管理类"""
    
    def __init__(self):
        """初始化IPv6地址池"""
        self.active_addresses = {}  # {address: last_verified_time}
        self.system_addresses = []  # 系统中实际存在的地址列表
        self.lock = asyncio.Lock()
        self.pool_size = config.proxy.local_ipv6_pool.pool_num
        self.check_interval = config.proxy.local_ipv6_pool.check_interval
        self.network_card = config.proxy.local_ipv6_pool.ipv6_network_card
        self._maintenance_task = None
        self._last_prefix = None  # 记录上次的IPv6前缀
        self._last_prefixes = set()  # 当前确认可用的所有 /64 前缀
        self._on_change_callbacks = []  # 地址变更回调列表（如通知beian刷新）
        self._last_add_fail_time = 0.0  # 补池失败退避时间戳
        self._pending_replacements = set()  # 正在后台替换的地址
        self._replacement_tasks = set()  # 后台替换任务引用，防止被GC
        
    def add_change_callback(self, callback):
        """注册地址变更回调（如 beian.refresh_ipv6_addresses）"""
        if callback not in self._on_change_callbacks:
            self._on_change_callbacks.append(callback)
    
    async def _notify_change(self):
        """通知所有回调地址已变更"""
        for cb in self._on_change_callbacks:
            try:
                cb()  # refresh_ipv6_addresses 是同步方法
            except Exception as e:
                logger.warning(f"地址变更回调失败: {e}")
    
    async def _discover_working_prefixes(self) -> List[str]:
        """
        探测哪些 /64 前缀真正可达。
        系统上可能有多个不同前缀的 IPv6（家宽 + 手机 USB 网络等），
        所有可达前缀都应保留，供查询 worker 分散出口使用。
        """
        # 按 /64 前缀分组
        prefix_groups: dict[str, list[str]] = {}
        for addr in self.system_addresses:
            pfx = self._extract_prefix(addr)
            prefix_groups.setdefault(pfx, []).append(addr)
        
        if len(prefix_groups) <= 1:
            # 只有一个前缀，直接返回
            return list(prefix_groups.keys())
        
        logger.info(f"检测到 {len(prefix_groups)} 个不同的IPv6前缀，开始探测可用性...")
        
        working_prefixes = []
        dead_prefixes = []
        
        for pfx, addrs in prefix_groups.items():
            sample = addrs[0]
            logger.info(f"  测试前缀 {pfx}::/64 ({len(addrs)}个地址)，抽样: {sample[-20:]}")
            if await self._verify_ipv6_address(sample):
                logger.info(f"  ✅ 前缀 {pfx}::/64 可达")
                working_prefixes.append((pfx, addrs))
            else:
                logger.warning(f"  ❌ 前缀 {pfx}::/64 不可达")
                dead_prefixes.append((pfx, addrs))
        
        if not working_prefixes:
            logger.error("所有IPv6前缀均不可达！")
            return None
        
        # 清理不可达前缀的地址（从系统中移除）
        for dead_pfx, dead_addrs in dead_prefixes:
            logger.warning(f"清理失效前缀 {dead_pfx}::/64 的 {len(dead_addrs)} 个地址...")
            await self._remove_dead_addresses(dead_addrs)
        
        chosen = [pfx for pfx, _ in working_prefixes]
        logger.info(f"选择可用前缀: {', '.join(f'{p}::/64' for p in chosen)}")
        return chosen
    
    async def _remove_dead_addresses(self, addresses: list[str]):
        """从系统中移除失效的IPv6地址"""
        if not addresses:
            return

        async def delete_one(addr):
            try:
                await asyncio.to_thread(
                    sp.run,
                    [
                        "netsh", "interface", "ipv6", "delete", "address",
                        self.network_card, addr,
                    ],
                    stdout=sp.DEVNULL,
                    stderr=sp.DEVNULL,
                    timeout=5,
                )
                return addr
            except Exception:
                return None

        # 系统级地址删除是真正慢且占资源的地方，限制并发到 8，
        # 避免像一次性 5000+ 删除那样把网卡状态机打满。
        sem = asyncio.Semaphore(8)

        async def limited(addr):
            async with sem:
                return await delete_one(addr)

        results = await asyncio.gather(*(limited(addr) for addr in addresses))
        removed = [r for r in results if r]
        if removed:
            logger.info(f"已从系统清理 {len(removed)} 个失效IPv6地址")
            await self._refresh_system_addresses()

    async def _trim_system_managed_addresses(self):
        """把系统网卡上的手工 IPv6 地址同步到 active_addresses 上限。

        这是修复“任务运行后网卡上不断堆积、却不删除旧地址”的关键。
        只删 Manual/手动地址，保留路由器公告的 Public/Temporary 基础地址。
        """
        keep = set(self.active_addresses.keys())
        managed = await asyncio.to_thread(
            get_manual_ipv6_addresses, self.network_card
        )
        # 保护：只有手工地址数量真正超过活跃池上限时才清理，
        # 避免“系统/活跃数量相等但集合不完全一致”时每轮删一个地址造成的抖动。
        # 只有手工地址明显超过活跃池（+2 冗余）时才清理，
        # 防止系统/活跃集合仅轻微不一致时每轮都删一个地址。
        if len(managed) <= len(keep) + 2:
            return
        # 只删本程序当前能看见的系统地址，避免误伤其它网卡。
        system_set = set(self.system_addresses)
        to_delete = [addr for addr in managed
                     if addr in system_set and addr not in keep]
        if not to_delete:
            return
        logger.info(f"🧹 检测到系统中有 {len(managed)} 个手工IPv6地址，"
                    f"活动池仅保留 {len(keep)} 个，准备清理 {len(to_delete)} 个多余地址")
        await self._remove_dead_addresses(to_delete)
    
    async def initialize(self):
        """初始化地址池"""
        logger.info("初始化IPv6地址池...")
        
        # 获取系统中现有的IPv6地址
        await self._refresh_system_addresses()
        
        if not self.system_addresses:
            logger.error("未找到任何公网IPv6地址,无法启用IPv6池")
            return False
        
        # 检测是否存在永久有效的IPv6地址（云服务器特征）
        has_permanent, sample_addr = check_has_permanent_ipv6()
        if has_permanent:
            logger.warning("=" * 80)
            logger.warning("⚠️  检测到系统中存在永久有效的IPv6地址（valid_lft forever）")
            logger.warning(f"⚠️  地址: {sample_addr}")
            logger.warning("⚠️  这通常说明您正在使用云服务器环境（如阿里云、腾讯云等）")
            logger.warning("⚠️  在云服务器环境中，新增的IPv6地址可能需要通过云服务商控制台配置才能使用")
            logger.warning("⚠️  如果遇到新增IPv6地址无法访问外网的情况，请联系您的云服务提供商")
            logger.warning("⚠️  或在云服务商控制台中为您的实例分配和绑定IPv6地址段")
            logger.warning("=" * 80)
        
        # 🔧 自动探测可用前缀（支持多前缀环境，保留所有可达出口）
        working_prefixes = await self._discover_working_prefixes()
        if not working_prefixes:
            logger.error("未找到任何可达的IPv6前缀，无法启用IPv6池")
            return False
        
        self._last_prefixes = set(working_prefixes)
        self._last_prefix = working_prefixes[0]
        logger.info(f"使用IPv6前缀: {', '.join(f'{p}::/64' for p in working_prefixes)}")
        
        # 验证现有地址的可用性
        logger.info(f"开始验证 {len(self.system_addresses)} 个系统IPv6地址的可用性...")
        verified_count = 0
        
        # 并发验证所有地址（限制并发数为5）
        semaphore = asyncio.Semaphore(5)
        
        async def verify_and_add(addr):
            nonlocal verified_count
            async with semaphore:
                # 首先检查网段是否为公网
                if not is_public_ipv6(addr):
                    logger.warning(f"IPv6地址不是公网地址（网段检测）: {addr}")
                    return False
                # 快速验证：抽样测试IP实际可达性（前5个IP做真实测试）
                if verified_count < 5:
                    if await self._verify_ipv6_address(addr):
                        self.active_addresses[addr] = time.time()
                        verified_count += 1
                        logger.info(f"✓ IPv6地址可用: {addr}")
                        return True
                    else:
                        logger.warning(f"✗ IPv6地址不可达: {addr}")
                        return False
                else:
                    # 抽样通过后，其余IP信任系统配置
                    self.active_addresses[addr] = time.time()
                    verified_count += 1
                    logger.info(f"✓ IPv6地址可用: {addr}")
                    return True
        
        # 并发验证所有地址
        tasks = [verify_and_add(addr) for addr in self.system_addresses]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"验证完成：{verified_count}/{len(self.system_addresses)} 个地址可用")
        
        if verified_count == 0:
            logger.error("没有任何可用的公网IPv6地址，无法启用IPv6池")
            return False

        # 池容量裁剪：系统地址可能多于 pool_num（如历史遗留604个、现在配300），
        # 随机保留 pool_num 个，让每次任务的出口集合可控。
        self._cap_pool()

        # 只裁剪 Python 字典是不够的，必须把系统网卡上多余的手工地址真正删掉，
        # 否则旧任务会无限累积 IPv6，最终拖垮本机网络栈。
        await self._trim_system_managed_addresses()
        
        # 如果地址数量不足，自动补充
        if len(self.active_addresses) < self.pool_size:
            needed = self.pool_size - len(self.active_addresses)
            logger.info(f"当前有 {len(self.active_addresses)} 个可用IPv6地址，需要补充 {needed} 个")
            await self._add_addresses(needed)
        else:
            logger.info(f"已有 {len(self.active_addresses)} 个可用IPv6地址，满足需求(池上限{self.pool_size})")
        
        # 启动维护任务
        await self.start_maintenance()
        return True

    def _cap_pool(self):
        """把活跃池裁剪到 pool_size 以内。
        优先保留小前缀（如手机/其他运营商的独立出口，通常只有1~2个地址），
        剩余名额从最大前缀随机补足。供初始化/前缀变化/维护时调用。"""
        if len(self.active_addresses) <= self.pool_size:
            return
        groups = {}
        for k in self.active_addresses:
            pfx = ":".join(k.split(":")[:4])
            groups.setdefault(pfx, []).append(k)
        import random as _random
        keep = []
        # 小前缀优先全保留（独立出口，丢了就少一个窗口）
        for pfx, addrs in sorted(groups.items(), key=lambda x: len(x[1])):
            if len(keep) + len(addrs) <= self.pool_size:
                keep.extend(addrs)
            else:
                break
        # 剩余名额从最大前缀随机补足
        remaining = self.pool_size - len(keep)
        if remaining > 0:
            big = max(groups.items(), key=lambda x: len(x[1]))[1]
            _random.shuffle(big)
            keep.extend(big[:remaining])
        keep_set = set(keep)
        removed = [k for k in self.active_addresses if k not in keep_set]
        self.active_addresses = {k: self.active_addresses[k] for k in keep}
        logger.info(f"✂️ IPv6池裁剪: {len(keep)+len(removed)} -> {len(keep)} "
                    f"(保留前缀数{len(groups)}个，移除{len(removed)}个，池上限{self.pool_size})")
    
    async def _refresh_system_addresses(self):
        """刷新系统中实际存在的IPv6地址"""
        all_addresses = await asyncio.to_thread(get_local_ipv6_addresses)
        self.system_addresses = [addr for addr in all_addresses if is_public_ipv6(addr)]
        logger.debug(f"系统中有 {len(self.system_addresses)} 个公网IPv6地址")
    
    def _extract_prefix(self, address: str) -> str:
        """提取IPv6地址的前64位前缀"""
        parts = address.split(":")
        return ":".join(parts[0:4])
    
    async def _verify_ipv6_address(self, address: str) -> bool:
        """
        验证IPv6地址是否真的可用（公网可达）
        通过绑定指定IPv6地址访问 ifconfig.me，检查返回的IP是否匹配
        """
        try:
            # 创建一个绑定到指定IPv6地址的连接器
            connector = aiohttp.TCPConnector(
                family=socket.AF_INET6,
                local_addr=(address, 0),
                ssl=False
            )
            
            timeout = aiohttp.ClientTimeout(total=5)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # 使用 ifconfig.me 检测出口IP
                async with session.get('https://ifconfig.me/ip') as resp:
                    if resp.status == 200:
                        detected_ip = (await resp.text()).strip()
                        
                        # 检查返回的IP是否与指定的IPv6地址匹配
                        if detected_ip == address:
                            logger.debug(f"IPv6地址验证成功: {address}")
                            return True
                        else:
                            logger.warning(f"IPv6地址验证失败: {address}, 检测到的IP: {detected_ip}")
                            return False
                    else:
                        logger.warning(f"IPv6地址验证失败: {address}, HTTP状态码: {resp.status}")
                        return False
                        
        except asyncio.TimeoutError:
            logger.warning(f"IPv6地址验证超时: {address}")
            return False
        except Exception as e:
            logger.warning(f"IPv6地址验证出错: {address}, 错误: {e}")
            return False
    
    async def _add_addresses(self, count: int):
        """添加指定数量的IPv6地址（不再校验新地址，只要本地存在且为公网地址就加入池）"""
        if not self._last_prefix:
            logger.error("无法添加IPv6地址：未知前缀")
            return 0

        logger.info(f"尝试添加 {count} 个IPv6地址...")
        added = 0
        # 不要为了补几百个地址同步空转；每次只小批量补，失败就退避。
        # 扩大尝试次数与失败容忍，给 DAD(重复地址检测) 留足时间，
        # 否则新增 IPv6 在短暂 Tentative 状态会被误判为“未检测到”而提前放弃。
        max_attempts = min(max(1, count * 2), 200)
        attempts = 0
        consecutive_fail = 0

        while added < count and attempts < max_attempts:
            attempts += 1
            try:
                # 生成新地址
                await asyncio.to_thread(
                    configure_ipv6_addresses,
                    self._last_prefix,
                    1,
                    self.network_card,
                )
                await asyncio.sleep(0.2)  # 等待系统应用配置

                # 重新获取系统地址
                old_system_addresses = set(self.system_addresses)
                await self._refresh_system_addresses()

                # 找出新增的地址
                new_addresses = set(self.system_addresses) - old_system_addresses - set(self.active_addresses.keys())

                if new_addresses:
                    consecutive_fail = 0
                    for new_addr in new_addresses:
                        # 只要本地存在且为公网地址就直接加入池
                        if is_public_ipv6(new_addr):
                            self.active_addresses[new_addr] = time.time()
                            logger.info(f"✓ 成功添加IPv6地址: {new_addr}")
                            added += 1
                            break
                        else:
                            logger.warning(f"新添加的IPv6地址不是公网地址: {new_addr}")
                else:
                    consecutive_fail += 1
                    logger.warning(f"添加IPv6地址可能失败，未检测到新地址（尝试 {attempts}/{max_attempts}）")
                    if consecutive_fail >= 20:
                        logger.warning("连续多次未检测到新IPv6地址，暂停补池，避免空转")
                        break

            except Exception as e:
                logger.error(f"添加IPv6地址时出错: {e}")

            # 如果还需要继续添加，短暂等待
            if added < count:
                await asyncio.sleep(0.2)

        logger.info(f"添加完成：成功 {added}/{count} 个，共尝试 {attempts} 次")
        return added
    
    async def _cleanup_invalid_addresses(self):
        """清理失效的IPv6地址"""
        async with self.lock:
            # 刷新系统地址列表
            await self._refresh_system_addresses()
            system_addr_set = set(self.system_addresses)
            
            # 检查活跃池中的地址
            invalid_addresses = []
            for addr in list(self.active_addresses.keys()):
                if addr not in system_addr_set:
                    invalid_addresses.append(addr)
            
            # 移除失效地址
            if invalid_addresses:
                for addr in invalid_addresses:
                    del self.active_addresses[addr]
                    logger.warning(f"IPv6地址已失效，已移除: {addr}")
                logger.info(f"清理了 {len(invalid_addresses)} 个失效的IPv6地址")
            
            return len(invalid_addresses)

    async def replace_blocked_address(self, addr: str) -> Optional[str]:
        """安排后台替换被封地址（不阻塞查询热路径）。

        当上游把某个 IP 拉黑 30 分钟时，继续保留该地址只会让固定大小的
        IPv6 池慢慢耗尽，最终所有 worker 都在“等待 IP 恢复”中空转。
        策略：立即返回，后台先补一个新地址，补成功后才删除被封地址；
        补失败（如权限不足）则保留旧地址仅做冷却标记，等30分钟自然恢复，
        池子容量不受损，也不会让查询线程干等。
        """
        if not addr:
            return None
        if addr not in self.active_addresses or addr in self._pending_replacements:
            return None
        # 补池失败后退避30秒，避免大量429瞬间触发后台任务风暴
        if time.time() - self._last_add_fail_time < 30:
            return None
        # 限制并发替换任务数（查询消耗快，提高并行度避免池缩水）
        if len(self._replacement_tasks) >= 8:
            return None
        self._pending_replacements.add(addr)
        task = asyncio.create_task(self._do_replace_blocked(addr))
        self._replacement_tasks.add(task)
        task.add_done_callback(self._replacement_tasks.discard)
        return None

    async def _do_replace_blocked(self, addr: str):
        """后台执行替换：先补新地址，成功后再删除被封地址。"""
        try:
            async with self.lock:
                if addr not in self.active_addresses:
                    return
                old_active = set(self.active_addresses.keys())
                added = await self._add_addresses(1)
                if added <= 0:
                    # 补失败：保留旧地址，等30分钟冷却自然恢复，池容量不缩水
                    self._last_add_fail_time = time.time()
                    logger.warning(f"⚠️ 补充IPv6失败，暂不删除被封地址: {addr[-12:]}")
                    return
                fresh = set(self.active_addresses.keys()) - old_active
                new_addr = next(iter(fresh), None)

                # 补成功后才删除被封地址
                self.active_addresses.pop(addr, None)
                try:
                    if os.name == 'nt':
                        await asyncio.to_thread(
                            sp.run,
                            [
                                "netsh", "interface", "ipv6", "delete", "address",
                                self.network_card, addr,
                            ],
                            stdout=sp.DEVNULL,
                            stderr=sp.DEVNULL,
                            timeout=5,
                        )
                    else:
                        await asyncio.to_thread(
                            sp.run,
                            ["ip", "-6", "addr", "del", addr, "dev", self.network_card],
                            stdout=sp.DEVNULL,
                            stderr=sp.DEVNULL,
                            timeout=5,
                        )
                except Exception as e:
                    logger.warning(f"删除被封IPv6地址失败(不影响继续): {addr} - {e}")
                await self._refresh_system_addresses()
                await self._notify_change()
                self._last_add_fail_time = 0.0
                logger.info(
                    f"♻️ 已替换被封IPv6: {addr[-12:]} -> "
                    f"{new_addr[-12:] if new_addr else '无'}"
                )
        except Exception as e:
            logger.warning(f"后台替换被封IPv6失败: {addr[-12:]} - {e}")
        finally:
            self._pending_replacements.discard(addr)
    
    async def _check_prefix_change(self):
        """检查系统 IPv6 前缀集合是否变化（只更新元数据，不丢可用前缀）。"""
        if not self.system_addresses:
            return False
        
        prefix_groups: dict[str, list[str]] = {}
        for addr in self.system_addresses:
            pfx = self._extract_prefix(addr)
            prefix_groups.setdefault(pfx, []).append(addr)
        
        current_prefixes = set(prefix_groups.keys())
        added = current_prefixes - self._last_prefixes
        removed = self._last_prefixes - current_prefixes

        if not added and not removed:
            return False

        if added:
            logger.info(f"检测到新增 IPv6 前缀: {', '.join(f'{p}::/64' for p in added)}")
        if removed:
            logger.warning(f"检测到 IPv6 前缀失效: {', '.join(f'{p}::/64' for p in removed)}")

        self._last_prefixes = current_prefixes
        if self._last_prefix not in current_prefixes:
            self._last_prefix = sorted(current_prefixes)[0]

        # 通知 beian 刷新地址列表
        await self._notify_change()
        return True
    
    async def maintain_pool(self):
        """维护地址池：清理失效地址并补充新地址"""
        try:
            # 1. 清理失效地址
            removed = await self._cleanup_invalid_addresses()
            
            # 2. 检查前缀是否变化
            prefix_changed = await self._check_prefix_change()

            # 2.5 仅当 active 池真的超过上限时才裁剪，避免每秒反复洗牌。
            self._cap_pool()

            # 系统地址可能因为历史遗留或异常未删干净，每次维护都同步一次。
            await self._trim_system_managed_addresses()
            
            # 3. 如果地址数量不足，补充新地址
            current_count = len(self.active_addresses)
            if current_count < self.pool_size:
                # 每次只补少量，避免单次维护循环同步空转几百次。
                needed = min(self.pool_size - current_count, 10)
                # 补池失败后退避30秒，避免权限/环境问题导致每秒重复空转刷日志
                if time.time() - self._last_add_fail_time < 30:
                    return
                logger.info(f"IPv6地址池不足，当前 {current_count}/{self.pool_size}，需要补充 {needed} 个")
                added = await self._add_addresses(needed)
                if added == 0:
                    self._last_add_fail_time = time.time()
                
                if added == 0 and current_count == 0:
                    logger.error("无法添加IPv6地址，地址池为空！")
            
            # 记录当前状态
            if removed > 0 or prefix_changed:
                logger.info(f"IPv6地址池维护完成：当前有 {len(self.active_addresses)} 个可用地址")
                
        except Exception as e:
            logger.error(f"维护IPv6地址池时出错: {e}")
    
    async def maintenance_loop(self):
        """地址池维护循环任务"""
        logger.info(f"IPv6地址池维护任务已启动，检查间隔: {self.check_interval}秒")
        
        while True:
            try:
                await asyncio.sleep(self.check_interval)
                await self.maintain_pool()
            except asyncio.CancelledError:
                logger.info("IPv6地址池维护任务已取消")
                break
            except Exception as e:
                logger.error(f"IPv6地址池维护任务出错: {e}")
                await asyncio.sleep(5)  # 出错后等待5秒再继续
    
    async def start_maintenance(self):
        """启动维护任务"""
        if self._maintenance_task is None or self._maintenance_task.done():
            self._maintenance_task = asyncio.create_task(self.maintenance_loop())
            logger.info("IPv6地址池维护任务已启动")
    
    async def stop_maintenance(self):
        """停止维护任务"""
        if self._maintenance_task and not self._maintenance_task.done():
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except asyncio.CancelledError:
                pass
            logger.info("IPv6地址池维护任务已停止")
    
    async def get_random_address(self) -> Optional[str]:
        """获取一个随机的IPv6地址"""
        async with self.lock:
            if not self.active_addresses:
                logger.error("IPv6地址池为空，无法获取地址")
                return None
            
            address = random.choice(list(self.active_addresses.keys()))
            logger.debug(f"使用IPv6地址: {address}")
            return address
    
    def get_address_count(self) -> int:
        """获取当前可用地址数量"""
        return len(self.active_addresses)
    
    def get_all_addresses(self) -> List[str]:
        """获取所有活跃地址"""
        return list(self.active_addresses.keys())


# 全局IPv6地址池实例
_ipv6_pool: Optional[IPv6AddressPool] = None


async def init_ipv6_pool(app):
    """初始化IPv6地址池（用于app启动时）"""
    global _ipv6_pool
    
    logger.info("启用本地IPv6地址池管理")
    _ipv6_pool = IPv6AddressPool()
    success = await _ipv6_pool.initialize()
    
    if success:
        app['ipv6_pool'] = _ipv6_pool
        logger.info(f"IPv6地址池初始化成功，当前有 {_ipv6_pool.get_address_count()} 个可用地址")
        
        # 🔥 将IPv6池注入 beian 并同步地址列表（修复前缀变更后地址过期问题）
        myicp = app.get('myicp')
        if myicp:
            myicp.set_ipv6_pool(_ipv6_pool)
            myicp.refresh_ipv6_addresses()
            _ipv6_pool.add_change_callback(myicp.refresh_ipv6_addresses)
            logger.info(f"✓ beian IPv6地址已同步: {len(myicp.local_ipv6_addresses)} 个")
    else:
        logger.error("IPv6地址池初始化失败")
        app['ipv6_pool'] = None


async def cleanup_ipv6_pool(app):
    """清理IPv6地址池（用于app关闭时）"""
    global _ipv6_pool
    
    if _ipv6_pool:
        await _ipv6_pool.stop_maintenance()
        logger.info("IPv6地址池已清理")


def get_ipv6_pool() -> Optional[IPv6AddressPool]:
    """获取全局IPv6地址池实例"""
    return _ipv6_pool
