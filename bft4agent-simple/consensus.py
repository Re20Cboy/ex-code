"""
完整的PBFT (Practical Byzantine Fault Tolerance) 共识协议实现

基于PBFT论文实现三阶段提交协议:
- PRE-PREPARE: 主节点分配序列号并广播pre-prepare消息
- PREPARE: 副本节点验证并广播prepare消息，收集2f条prepare消息
- COMMIT: 收到2f条prepare后广播commit，收集2f+1条commit后执行

包含视图更换机制处理主节点故障

v2.0 新增:
- DID 身份验证（参与共识前验证身份有效性）
- 加权投票（基于信誉的投票权重）
- 行为日志记录（全流程行为追踪）
- 信誉系统集成（共识后自动更新信誉）
- 激励分配（共识后自动分配奖惩）
"""

import time
import random
import hashlib
import threading
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field

from behavior_log import BehaviorEventType


class ReplicaState(Enum):
    """副本状态机"""
    IDLE = "idle"
    PRE_PREPARED = "pre-prepared"
    PREPARED = "prepared"
    COMMITTED = "committed"


class MessageType(Enum):
    """PBFT消息类型"""
    REQUEST = "REQUEST"
    PRE_PREPARE = "PRE-PREPARE"
    PREPARE = "PREPARE"
    COMMIT = "COMMIT"
    REPLY = "REPLY"
    VIEW_CHANGE = "VIEW-CHANGE"
    NEW_VIEW = "NEW-VIEW"


@dataclass
class PBFTMessage:
    """PBFT消息基类"""
    view: int
    sequence_number: int
    sender_id: str
    timestamp: float
    signature: str = ""
    digest: str = ""

    def __post_init__(self):
        """计算消息摘要"""
        if not self.digest:
            self.digest = self._compute_digest()

    def _compute_digest(self) -> str:
        """计算消息摘要（用于签名验证）"""
        content = f"{self.view}:{self.sequence_number}:{self.sender_id}:{self.timestamp}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class PrePrepareMessage(PBFTMessage):
    """PRE-PREPARE消息（主节点发送）"""
    task: Dict = None
    proposal: Dict = None
    message_type: str = MessageType.PRE_PREPARE.value


@dataclass
class PrepareMessage(PBFTMessage):
    """PREPARE消息（副本发送）"""
    digest: str = ""  # 对应pre-prepare消息的摘要
    decision: str = ""  # Y/N：对proposal的评价
    confidence: float = 0.0  # 置信度
    reason: str = ""  # 评价理由
    message_type: str = MessageType.PREPARE.value


@dataclass
class CommitMessage(PBFTMessage):
    """COMMIT消息（副本发送）"""
    digest: str = ""  # 对应pre-prepare消息的摘要
    decision: str = ""  # Y/N：最终确认的决策
    message_type: str = MessageType.COMMIT.value


@dataclass
class ViewChangeMessage(PBFTMessage):
    """VIEW-CHANGE消息（视图更换请求）"""
    new_view: int = 0
    checkpoint_message: str = ""
    message_type: str = MessageType.VIEW_CHANGE.value


@dataclass
class NewViewMessage(PBFTMessage):
    """NEW-VIEW消息（新主节点广播）"""
    new_view: int = 0
    view_change_messages: List[str] = field(default_factory=list)
    pre_prepare_message: str = ""
    message_type: str = MessageType.NEW_VIEW.value


class MessageLog:
    """消息日志 - 记录所有PBFT消息"""

    def __init__(self):
        self.pre_prepare: Dict[int, PrePrepareMessage] = {}
        self.prepare: Dict[int, Dict[str, PrepareMessage]] = {}
        self.commit: Dict[int, Dict[str, CommitMessage]] = {}
        self.view_changes: Dict[int, Dict[str, ViewChangeMessage]] = {}

    def add_pre_prepare(self, msg: PrePrepareMessage):
        """添加pre-prepare消息"""
        self.pre_prepare[msg.sequence_number] = msg

    def add_prepare(self, msg: PrepareMessage):
        """添加prepare消息"""
        if msg.sequence_number not in self.prepare:
            self.prepare[msg.sequence_number] = {}
        self.prepare[msg.sequence_number][msg.sender_id] = msg

    def add_commit(self, msg: CommitMessage):
        """添加commit消息"""
        if msg.sequence_number not in self.commit:
            self.commit[msg.sequence_number] = {}
        self.commit[msg.sequence_number][msg.sender_id] = msg

    def add_view_change(self, msg: ViewChangeMessage):
        """添加view-change消息"""
        if msg.new_view not in self.view_changes:
            self.view_changes[msg.new_view] = {}
        self.view_changes[msg.new_view][msg.sender_id] = msg

    def get_prepare_count(self, sequence_number: int, digest: str) -> int:
        """获取指定序列号和摘要的prepare消息数量"""
        if sequence_number not in self.prepare:
            return 0
        return sum(
            1 for msg in self.prepare[sequence_number].values()
            if msg.digest == digest
        )

    def get_commit_count(self, sequence_number: int, digest: str) -> int:
        """获取指定序列号和摘要的commit消息数量"""
        if sequence_number not in self.commit:
            return 0
        return sum(
            1 for msg in self.commit[sequence_number].values()
            if msg.digest == digest
        )

    def clear(self):
        """清空日志"""
        self.pre_prepare.clear()
        self.prepare.clear()
        self.commit.clear()
        self.view_changes.clear()


class Replica:
    """PBFT副本节点 - 包装Agent以支持PBFT协议"""

    def __init__(self, agent, is_primary: bool = False):
        self.agent = agent
        self.is_primary = is_primary
        self.state = ReplicaState.IDLE
        self.message_log = MessageLog()
        self.current_view = 0
        self.last_executed_sequence = 0

        # 用于等待消息的条件变量
        self.prepare_lock = threading.Lock()
        self.prepare_cond = threading.Condition(self.prepare_lock)
        self.commit_lock = threading.Lock()
        self.commit_cond = threading.Condition(self.commit_lock)


class BFT4Agent:
    """
    完整的PBFT共识协议实现

    三阶段提交流程:
    1. PRE-PREPARE: 主节点分配序列号，广播pre-prepare消息
    2. PREPARE: 副本验证并广播prepare，等待2f条prepare消息
    3. COMMIT: 收到2f条prepare后广播commit，等待2f+1条commit后执行

    视图更换: 检测到主节点故障时触发
    """

    def __init__(
        self,
        agents: List,
        network,
        f: Optional[int] = None,
        timeout: float = 5.0,
        max_retries: int = 3,
        did_registry=None,
        reputation_system=None,
        behavior_log=None,
        incentive_system=None,
        enable_weighted_voting: bool = True,
    ):
        """
        初始化PBFT协议

        Args:
            agents: Agent列表
            network: 网络实例
            f: 最大容忍故障节点数（默认为总节点数的1/4向下取整）
            timeout: 超时时间（秒）
            max_retries: 最大重试次数
            did_registry: DID注册表（可选，用于身份验证）
            reputation_system: 信誉系统（可选，用于加权投票）
            behavior_log: 行为日志（可选，用于行为追踪）
            incentive_system: 激励系统（可选，用于奖惩分配）
            enable_weighted_voting: 是否启用加权投票
        """
        self.agents = agents
        self.network = network
        self.timeout = timeout
        self.max_retries = max_retries

        # === DID / 信誉 / 行为日志 / 激励系统 ===
        self.did_registry = did_registry
        self.reputation_system = reputation_system
        self.behavior_log = behavior_log
        self.incentive_system = incentive_system
        self.enable_weighted_voting = enable_weighted_voting

        # PBFT参数
        self.total_nodes = len(agents)
        # PBFT要求总节点数 = 3f + 1，因此 f = (n-1) // 3
        # 但为了演示灵活，允许用户指定，默认使用 (n-1) // 3
        self.f = f if f is not None else (self.total_nodes - 1) // 3

        # Quorum要求
        # 需要至少2f+1个节点同意（包括自己）
        self.quorum_size = 2 * self.f + 1
        # Prepare阶段需要2f条prepare消息（不包括自己）
        self.prepare_quorum = 2 * self.f
        # Commit阶段需要2f+1条commit消息（包括自己）

        # 序列号管理
        self.global_sequence_number = 0
        self.sequence_lock = threading.Lock()

        # 视图管理
        self.current_view = 0

        # 创建副本包装器
        self.replicas: Dict[str, Replica] = {}
        for agent in agents:
            self.replicas[agent.id] = Replica(agent, is_primary=False)

        # 统计信息
        self.consensus_count = 0
        self.view_change_count = 0
        self.total_messages = 0

    def _get_primary_id(self, view: int) -> str:
        """根据视图号获取主节点ID（轮换主节点）"""
        primary_index = view % self.total_nodes
        return self.agents[primary_index].id

    def _assign_sequence_number(self) -> int:
        """分配全局序列号（线程安全）"""
        with self.sequence_lock:
            self.global_sequence_number += 1
            return self.global_sequence_number

    def _sign_message(self, message: PBFTMessage) -> str:
        """签名消息（Mock实现）"""
        # 实际系统应使用真实的数字签名算法
        content = f"{message.digest}:{message.sender_id}"
        return f"sig_{hashlib.md5(content.encode()).hexdigest()[:8]}"

    def _verify_signature(self, message: PBFTMessage) -> bool:
        """验证签名（Mock实现）"""
        # Mock实现：总是返回True
        return True

    def _send_message(self, message: PBFTMessage, recipient_id: str = None):
        """发送消息（单播或广播）"""
        message.signature = self._sign_message(message)
        self.total_messages += 1

        if recipient_id:
            # 单播
            self.network.send(
                {
                    "type": message.message_type,
                    "data": message,
                },
                sender_id=message.sender_id,
                recipient_id=recipient_id,
            )
        else:
            # 广播
            self.network.broadcast(
                {
                    "type": message.message_type,
                    "data": message,
                },
                sender_id=message.sender_id,
            )

    def run(self, task: Dict) -> Dict:
        """
        运行完整的PBFT共识流程

        核心设计：
        1. Leader生成proposal（包含答案和推理链路）
        2. Backup节点对proposal进行Y/N评价
        3. 通过BFT达成对Y/N的共识（而非对task内容的共识）
        4. 如果Y达到2f+1，返回答案；如果N达到f+1，触发视图切换

        Args:
            task: 任务字典 {"content": "...", "type": "..."}

        Returns:
            结果字典 {
                "success": True/False,
                "answer": "...",
                "view_changes": 0,
                "total_messages": 0,
                "total_time": 1.23,
                "proposal": {...},
                "phases": ["pre-prepare", "prepare", "commit"],
                "decision": "Y/N"  # 共识决策
            }
        """
        start_time = time.time()
        view_changes = 0
        message_count = 0
        phases_completed = []
        phase_times = {}  # 各阶段耗时记录

        print(f"\n{'='*60}")
        print(f"  开始BFT4Agent共识 - {task['content']}")
        print(f"  节点数: {self.total_nodes}, 容错数: f={self.f}")
        print(f"  Prepare阈值: {self.prepare_quorum}, Commit阈值: {self.quorum_size}")
        print(f"{'='*60}")

        # 尝试达成共识
        for attempt in range(self.max_retries):
            self.current_view = view_changes
            primary_id = self._get_primary_id(self.current_view)

            print(f"\n[视图 {self.current_view}] 主节点: {primary_id}")

            try:
                # === 修复BUG: 重置所有agent和replica的状态 ===
                self._reset_all_states()

                # 清空所有副本的消息日志
                for replica in self.replicas.values():
                    replica.message_log.clear()

                # === PHASE 1: PRE-PREPARE ===
                # Leader生成proposal并广播
                print(f"\n[阶段1] PRE-PREPARE - Leader生成提案")
                t_phase = time.time()
                pre_prepare_msg = self._pre_prepare_phase(primary_id, task)
                phase_times["pre_prepare"] = time.time() - t_phase
                if not pre_prepare_msg:
                    raise Exception("PRE-PREPARE阶段失败")

                phases_completed.append("pre-prepare")
                message_count += self.total_nodes  # 主节点广播给所有节点

                # === PHASE 2: PREPARE ===
                # Backup节点对proposal进行Y/N评价
                print(f"\n[阶段2] PREPARE - Backup节点评价提案")
                t_phase = time.time()
                prepare_success, prepare_decision = self._prepare_phase(pre_prepare_msg)
                phase_times["prepare"] = time.time() - t_phase
                if not prepare_success:
                    raise Exception("PREPARE阶段超时或未达到法定人数")

                phases_completed.append("prepare")
                message_count += self.total_nodes * self.total_nodes  # 每个节点广播prepare

                # === 核心判断：如果PREPARE阶段达成N共识，触发视图切换 ===
                if prepare_decision == "N":
                    print(f"\n[PREPARE] 达成N共识（拒绝提案），触发视图切换")
                    raise Exception(f"Proposal被拒绝（{self.f + 1}+个N投票）")

                # === PHASE 3: COMMIT ===
                # 所有节点对Y/N达成最终共识
                print(f"\n[阶段3] COMMIT - 对Y/N达成最终共识")
                t_phase = time.time()
                commit_success, final_decision = self._commit_phase(pre_prepare_msg, prepare_decision)
                phase_times["commit"] = time.time() - t_phase
                if not commit_success:
                    raise Exception("COMMIT阶段超时或未达到法定人数")

                phases_completed.append("commit")
                message_count += self.total_nodes * self.total_nodes  # 每个节点广播commit

                # === 核心判断：如果COMMIT阶段达成N共识，触发视图切换 ===
                if final_decision == "N":
                    print(f"\n[COMMIT] 达成N共识（拒绝提案），触发视图切换")
                    raise Exception(f"Proposal被拒绝（{self.f + 1}+个N投票）")

                # === 成功：Y共识达成，返回答案 ===
                self.consensus_count += 1
                total_time = time.time() - start_time
                message_count = self.total_messages

                result = {
                    "success": True,
                    "answer": pre_prepare_msg.proposal.get("answer"),
                    "view_changes": view_changes,
                    "total_messages": message_count,
                    "total_time": total_time,
                    "proposal": pre_prepare_msg.proposal,
                    "phases": phases_completed,
                    "primary_id": primary_id,
                    "sequence_number": pre_prepare_msg.sequence_number,
                    "decision": final_decision,  # "Y" or "N"
                    "phase_times": dict(phase_times),
                }

                # === 信誉更新、行为日志、激励分配 ===
                self._post_consensus_processing(
                    task=task,
                    result=result,
                    pre_prepare_msg=pre_prepare_msg,
                )

                print(f"\n{'='*60}")
                print(f"  [OK] BFT4Agent共识成功!")
                print(f"  共识决策: {final_decision} (接受提案)")
                print(f"  最终答案: {result['answer']}")
                print(f"  耗时: {total_time:.2f}秒")
                print(f"  消息数: {message_count}")
                print(f"  视图切换: {view_changes}次")
                print(f"{'='*60}\n")

                return result

            except Exception as e:
                print(f"\n[ERROR] 视图 {self.current_view} 失败: {e}")
                view_changes += 1
                self.view_change_count += 1
                self._trigger_view_change()

                # 如果达到最大重试次数，退出循环
                if view_changes >= self.max_retries:
                    break

        # 达到最大重试次数，仍然未达成共识
        total_time = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"  [FAIL] BFT4Agent共识失败（超过最大重试次数）")
        print(f"{'='*60}\n")

        return {
            "success": False,
            "answer": None,
            "view_changes": view_changes,
            "total_messages": message_count,
            "total_time": total_time,
            "error": "Max retries exceeded",
            "phases": phases_completed,
            "decision": "N",
            "phase_times": dict(phase_times),
        }

    def _pre_prepare_phase(self, primary_id: str, task: Dict) -> Optional[PrePrepareMessage]:
        """
        PRE-PREPARE阶段

        主节点:
        1. 分配序列号
        2. 调用Agent生成提案
        3. 广播PRE-PREPARE消息给所有副本
        """
        primary_replica = self.replicas[primary_id]
        primary_replica.is_primary = True

        # 设置Agent的role为leader（propose方法需要）
        primary_replica.agent.role = "leader"

        # 打印节点信息
        malicious_flag = " [恶意]" if primary_replica.agent.is_malicious else ""
        specialty = primary_replica.agent.role_config.get("name", "通用")
        print(f"[{primary_id}] 角色信息: {specialty}, is_malicious={primary_replica.agent.is_malicious}{malicious_flag}")

        # 分配序列号
        sequence_number = self._assign_sequence_number()
        print(f"[{primary_id}] 分配序列号: {sequence_number}")

        # 生成提案
        print(f"[{primary_id}] 正在生成提案...")
        proposal = primary_replica.agent.propose(task)

        # 打印提案详细内容
        print(f"\n{'='*80}")
        print(f"[Leader提案内容] {primary_id}")
        print(f"{'='*80}")
        print(f"问题ID: {proposal.get('task_id', 'N/A')}")
        print(f"问题内容: {proposal.get('task_content', 'N/A')[:100]}...")
        print(f"Leader答案: {proposal.get('answer', 'N/A')}")
        print(f"推理过程:")
        reasoning = proposal.get('reasoning', [])
        if isinstance(reasoning, list):
            for i, step in enumerate(reasoning, 1):
                print(f"  {i}. {step}")
        else:
            print(f"  {reasoning}")
        print(f"置信度: {proposal.get('confidence', 'N/A')}")
        print(f"{'='*80}\n")

        # 创建PRE-PREPARE消息
        pre_prepare_msg = PrePrepareMessage(
            view=self.current_view,
            sequence_number=sequence_number,
            sender_id=primary_id,
            timestamp=time.time(),
            task=task,
            proposal=proposal,
        )

        # 记录到主节点日志
        primary_replica.message_log.add_pre_prepare(pre_prepare_msg)
        primary_replica.state = ReplicaState.PRE_PREPARED

        # 广播PRE-PREPARE消息
        print(f"[{primary_id}] 广播PRE-PREPARE消息")
        self._send_message(pre_prepare_msg)

        return pre_prepare_msg

    def _prepare_phase(self, pre_prepare_msg: PrePrepareMessage) -> Tuple[bool, str]:
        """
        PREPARE阶段

        副本节点:
        1. 验证PRE-PREPARE消息
        2. 对proposal进行Y/N评价（调用validate方法）
        3. 广播包含Y/N评价的PREPARE消息
        4. 统计Y/N投票数量

        注意：Leader不参与PREPARE投票，只有Backup节点参与

        Returns:
            (success, consensus_decision): 是否达成共识，以及共识结果（"Y"或"N"）
        """
        digest = pre_prepare_msg.digest
        sequence_number = pre_prepare_msg.sequence_number
        primary_id = pre_prepare_msg.sender_id

        # === 关键修改：Leader不参与PREPARE投票 ===
        # 只有backup节点对proposal进行评价
        prepare_messages = []
        threads = []

        # 只有backup节点参与评价（跳过Leader）
        for replica_id, replica in self.replicas.items():
            if replica_id == primary_id:
                print(f"[{primary_id}] Leader不参与PREPARE投票")
                continue  # 跳过Leader

            thread = threading.Thread(
                target=self._replica_prepare_phase,
                args=(replica, pre_prepare_msg, prepare_messages)
            )
            threads.append(thread)
            thread.start()

        # 等待所有副本完成PREPARE阶段
        print(f"[PREPARE] 等待 {len(threads)} 个节点完成评价（超时: {self.timeout}秒）...")
        completed_threads = 0
        for thread in threads:
            thread.join(timeout=self.timeout)
            if not thread.is_alive():
                completed_threads += 1

        print(f"[PREPARE] {completed_threads}/{len(threads)} 个节点在超时前完成")

        # 额外等待一段时间，收集可能延迟到达的消息
        # 这是因为真实LLM API调用可能比timeout慢，但我们仍然希望收集到足够多的投票
        if completed_threads < len(threads):
            wait_time = min(5.0, self.timeout)  # 最多额外等待5秒
            print(f"[PREPARE] 额外等待 {wait_time}秒 以收集更多投票...")
            time.sleep(wait_time)

        # 模拟网络消息传递：将所有PREPARE消息分发给所有副本
        print(f"[PREPARE] 分发{len(prepare_messages)}条PREPARE消息到所有节点")
        for prep_msg in prepare_messages:
            for replica in self.replicas.values():
                replica.message_log.add_prepare(prep_msg)

        # 等待所有副本处理接收到的PREPARE消息
        time.sleep(0.5)

        # === 核心修改：统计Y/N投票数量（支持加权投票）===
        if self.enable_weighted_voting and self.reputation_system:
            # 加权投票模式：使用信誉权重
            y_weight = 0.0
            n_weight = 0.0
            total_weight = 0.0
            weights = self.reputation_system.compute_all_weights()

            for prep_msg in prepare_messages:
                w = weights.get(prep_msg.sender_id, 0.0)
                total_weight += w
                if prep_msg.decision == "Y":
                    y_weight += w
                elif prep_msg.decision == "N":
                    n_weight += w

            y_count = sum(1 for m in prepare_messages if m.decision == "Y")
            n_count = sum(1 for m in prepare_messages if m.decision == "N")

            print(f"[PREPARE] 加权投票统计: Y={y_count}(权重={y_weight:.3f}), N={n_count}(权重={n_weight:.3f}), 总权重={total_weight:.3f}")

            # 加权法定人数检查
            # Y权重 >= 2/3 总权重 → 接受
            # N权重 >= 1/3 总权重 → 拒绝
            prepared_count = 0
            consensus_decision = ""

            if total_weight > 0 and y_weight >= (2.0/3.0) * total_weight:
                prepared_count = self.total_nodes
                consensus_decision = "Y"
                print(f"[PREPARE] 达到Y加权法定人数 ({y_weight:.3f} >= {2.0/3.0 * total_weight:.3f})，接受proposal")
            elif total_weight > 0 and n_weight >= (1.0/3.0) * total_weight:
                consensus_decision = "N"
                print(f"[PREPARE] 达到N加权阈值 ({n_weight:.3f} >= {1.0/3.0 * total_weight:.3f})，拒绝proposal")
                return (True, consensus_decision)
            else:
                print(f"[PREPARE] 未达成加权共识 (Y权重={y_weight:.3f}, N权重={n_weight:.3f})")
                return (False, "")
        else:
            # 传统模式：一人一票
            y_count = 0
            n_count = 0
            for prep_msg in prepare_messages:
                if prep_msg.decision == "Y":
                    y_count += 1
                elif prep_msg.decision == "N":
                    n_count += 1

            print(f"[PREPARE] 投票统计: Y={y_count}, N={n_count}")

            # 检查是否达到法定人数要求
            prepared_count = 0
            consensus_decision = ""

            if y_count >= self.quorum_size:
                prepared_count = self.total_nodes
                consensus_decision = "Y"
                print(f"[PREPARE] 达到Y法定人数 ({y_count} >= {self.quorum_size})，接受proposal")
            elif n_count >= (self.f + 1):
                consensus_decision = "N"
                print(f"[PREPARE] 达到N阈值 ({n_count} >= {self.f + 1})，拒绝proposal")
                return (True, consensus_decision)
            else:
                print(f"[PREPARE] 未达成共识 (Y={y_count}, N={n_count})")
                return (False, "")

        # 更新所有副本状态
        for replica in self.replicas.values():
            prep_count = replica.message_log.get_prepare_count(sequence_number, digest)
            print(f"  [{replica.agent.id}] 收到{prep_count}条PREPARE消息")
            if prep_count >= self.prepare_quorum:
                replica.state = ReplicaState.PREPARED
                prepared_count += 1

        success = prepared_count >= self.quorum_size
        print(f"[PREPARE] {prepared_count}/{self.total_nodes} 节点达到prepared状态")

        return (success, consensus_decision)

    def _replica_prepare_phase(self, replica: Replica, pre_prepare_msg: PrePrepareMessage, prepare_messages: list):
        """
        单个副本的PREPARE阶段逻辑

        关键修改：这里调用agent.validate()对proposal进行Y/N评价
        """
        # 记录PRE-PREPARE消息
        replica.message_log.add_pre_prepare(pre_prepare_msg)
        replica.state = ReplicaState.PRE_PREPARED

        # 验证PRE-PREPARE消息签名
        if not self._verify_signature(pre_prepare_msg):
            print(f"[{replica.agent.id}] PRE-PREPARE签名验证失败")
            return

        # === 核心设计：对proposal进行语义验证，获取Y/N评价 ===
        proposal = pre_prepare_msg.proposal
        print(f"[{replica.agent.id}] 正在评价proposal...")

        # === DID 身份验证 ===
        if self.did_registry and replica.agent.did:
            valid, reason_msg = self.did_registry.verify_identity(replica.agent.did)
            if not valid:
                print(f"[{replica.agent.id}] DID身份验证失败: {reason_msg}，跳过投票")
                # 记录行为日志
                if self.behavior_log and replica.agent.did:
                    self.behavior_log.record(
                        agent_id=replica.agent.id,
                        did=replica.agent.did,
                        event_type=BehaviorEventType.TIMEOUT if "暂停" in reason_msg else BehaviorEventType.OFFLINE,
                        task_id=proposal.get("task_id", ""),
                        view=self.current_view,
                        details={"reason": f"DID验证失败: {reason_msg}"},
                    )
                return

        # 调用agent的validate方法获取Y/N决策
        vote = replica.agent.validate(proposal)
        decision = vote.get("decision", "N")  # Y or N
        confidence = vote.get("confidence", 0.0)
        reason = vote.get("reason", "")

        print(f"[{replica.agent.id}] 评价结果: {decision} (置信度: {confidence:.2f})")

        # === 记录行为日志 ===
        if self.behavior_log and replica.agent.did:
            self.behavior_log.record_vote(
                agent_id=replica.agent.id,
                did=replica.agent.did,
                task_id=proposal.get("task_id", ""),
                view=self.current_view,
                seq=pre_prepare_msg.sequence_number,
                decision=decision,
                confidence=confidence,
                reason=reason,
            )

        # 创建PREPARE消息，包含Y/N评价
        prepare_msg = PrepareMessage(
            view=self.current_view,
            sequence_number=pre_prepare_msg.sequence_number,
            sender_id=replica.agent.id,
            timestamp=time.time(),
            digest=pre_prepare_msg.digest,
            decision=decision,
            confidence=confidence,
            reason=reason,
        )

        # 记录自己的PREPARE消息
        replica.message_log.add_prepare(prepare_msg)
        print(f"[{replica.agent.id}] 创建PREPARE消息 (决策: {decision})")

        # 将消息添加到共享列表（用于后续分发给所有副本）
        prepare_messages.append(prepare_msg)

    def _wait_for_prepares(self, replica: Replica, sequence_number: int, digest: str):
        """等待收集2f条PREPARE消息"""
        start_time = time.time()
        timeout_event = threading.Event()

        def check_prepare_count():
            while replica.message_log.get_prepare_count(sequence_number, digest) < self.prepare_quorum:
                if time.time() - start_time > self.timeout:
                    print(f"[{replica.agent.id}] PREPARE等待超时")
                    return
                time.sleep(0.1)

            # 达到法定人数
            replica.state = ReplicaState.PREPARED
            print(f"[{replica.agent.id}] 达到prepared状态")
            timeout_event.set()

        check_thread = threading.Thread(target=check_prepare_count)
        check_thread.start()
        timeout_event.wait(timeout=self.timeout + 1)

    def _commit_phase(self, pre_prepare_msg: PrePrepareMessage, prepare_decision: str) -> Tuple[bool, str]:
        """
        COMMIT阶段

        所有节点:
        1. 收到2f条PREPARE后进入prepared状态
        2. 基于PREPARE阶段的评价结果，广播COMMIT消息（包含最终决策）
        3. 等待收集2f+1条COMMIT消息
        4. 统计Y/N的COMMIT消息数量，达成最终共识

        Args:
            pre_prepare_msg: PRE-PREPARE消息
            prepare_decision: PREPARE阶段的共识决策（"Y"或"N"）

        Returns:
            (success, final_decision): 是否达成共识，以及最终决策（"Y"或"N"）
        """
        digest = pre_prepare_msg.digest
        sequence_number = pre_prepare_msg.sequence_number

        # 每个节点发送COMMIT消息
        commit_messages = []
        threads = []
        for replica_id, replica in self.replicas.items():
            thread = threading.Thread(
                target=self._replica_commit_phase,
                args=(replica, pre_prepare_msg, commit_messages, prepare_decision)
            )
            threads.append(thread)
            thread.start()

        # 等待所有节点完成COMMIT阶段
        print(f"[COMMIT] 等待 {len(threads)} 个节点完成提交（超时: {self.timeout}秒）...")
        completed_threads = 0
        for thread in threads:
            thread.join(timeout=self.timeout)
            if not thread.is_alive():
                completed_threads += 1

        print(f"[COMMIT] {completed_threads}/{len(threads)} 个节点在超时前完成")

        # 额外等待一段时间，收集可能延迟到达的消息
        if completed_threads < len(threads):
            wait_time = min(5.0, self.timeout)  # 最多额外等待5秒
            print(f"[COMMIT] 额外等待 {wait_time}秒 以收集更多投票...")
            time.sleep(wait_time)

        # 模拟网络消息传递：将所有COMMIT消息分发给所有副本
        print(f"[COMMIT] 分发{len(commit_messages)}条COMMIT消息到所有节点")
        for commit_msg in commit_messages:
            for replica in self.replicas.values():
                replica.message_log.add_commit(commit_msg)

        # 等待所有副本处理接收到的COMMIT消息
        time.sleep(0.5)

        # === 核心修改：统计Y/N的COMMIT消息数量 ===
        y_count = 0
        n_count = 0
        for commit_msg in commit_messages:
            if commit_msg.decision == "Y":
                y_count += 1
            elif commit_msg.decision == "N":
                n_count += 1

        print(f"[COMMIT] 投票统计: Y={y_count}, N={n_count}")

        # 检查是否达到法定人数
        final_decision = ""
        committed_count = 0

        if y_count >= self.quorum_size:
            # Y达到法定人数，最终接受proposal
            final_decision = "Y"
            print(f"[COMMIT] 达到Y法定人数 ({y_count} >= {self.quorum_size})，最终接受proposal")
            for replica in self.replicas.values():
                replica.state = ReplicaState.COMMITTED
                committed_count += 1
        elif n_count >= (self.f + 1):
            # N达到阈值，最终拒绝proposal（将触发视图切换）
            final_decision = "N"
            print(f"[COMMIT] 达到N阈值 ({n_count} >= {self.f + 1})，最终拒绝proposal")
            return (True, final_decision)
        else:
            # 未达成共识
            print(f"[COMMIT] 未达成共识 (Y={y_count}, N={n_count})")
            return (False, "")

        success = committed_count >= self.quorum_size
        print(f"[COMMIT] {committed_count}/{self.total_nodes} 节点达到committed状态")

        return (success, final_decision)

    def _replica_commit_phase(self, replica: Replica, pre_prepare_msg: PrePrepareMessage, commit_messages: list, prepare_decision: str):
        """
        单个副本的COMMIT阶段逻辑

        Args:
            replica: 副本节点
            pre_prepare_msg: PRE-PREPARE消息
            commit_messages: COMMIT消息列表
            prepare_decision: PREPARE阶段的共识决策（"Y"或"N"）
        """
        digest = pre_prepare_msg.digest
        sequence_number = pre_prepare_msg.sequence_number

        # === 核心修改：节点根据PREPARE阶段的共识结果，决定自己的COMMIT决策 ===
        # 如果PREPARE阶段达成Y共识，则节点应该发送Y
        # 如果PREPARE阶段达成N共识，则节点应该发送N
        # 这里简化处理：使用PREPARE阶段的共识决策
        # 在实际实现中，节点也可以坚持自己的原始判断
        decision = prepare_decision

        # 创建COMMIT消息，包含最终决策
        commit_msg = CommitMessage(
            view=self.current_view,
            sequence_number=sequence_number,
            sender_id=replica.agent.id,
            timestamp=time.time(),
            digest=digest,
            decision=decision,
        )

        # 记录自己的COMMIT消息
        replica.message_log.add_commit(commit_msg)
        print(f"[{replica.agent.id}] 创建COMMIT消息 (决策: {decision})")

        # 将消息添加到共享列表（用于后续分发给所有副本）
        commit_messages.append(commit_msg)

    def _wait_for_commits(self, replica: Replica, sequence_number: int, digest: str):
        """等待收集2f+1条COMMIT消息"""
        start_time = time.time()

        def check_commit_count():
            while replica.message_log.get_commit_count(sequence_number, digest) < self.quorum_size:
                if time.time() - start_time > self.timeout:
                    print(f"[{replica.agent.id}] COMMIT等待超时")
                    return
                time.sleep(0.1)

            # 达到法定人数，执行请求
            replica.state = ReplicaState.COMMITTED
            replica.last_executed_sequence = sequence_number
            print(f"[{replica.agent.id}] 达到committed状态，执行请求")

        check_thread = threading.Thread(target=check_commit_count)
        check_thread.start()
        check_thread.join(timeout=self.timeout + 1)

    def _trigger_view_change(self):
        """触发视图更换"""
        print(f"\n[VIEW-CHANGE] 触发视图更换 {self.current_view} -> {self.current_view + 1}")

        # 在实际PBFT中，这里会:
        # 1. 所有节点广播VIEW-CHANGE消息
        # 2. 收集2f+1条VIEW-CHANGE消息
        # 3. 新主节点发送NEW-VIEW消息
        # 4. 重新开始PRE-PREPARE阶段

        # 简化实现：直接增加视图号
        time.sleep(0.5)  # 模拟视图更换延迟

    def _reset_all_states(self):
        """
        重置所有agent和replica的状态

        在视图切换时调用，确保：
        1. 所有agent的role重置为"backup"
        2. 所有replica的is_primary重置为False
        3. 所有replica的state重置为IDLE
        """
        print(f"[状态重置] 重置所有节点状态")

        # 重置所有agent的role
        for agent in self.agents:
            agent.role = "backup"

        # 重置所有replica的状态
        for replica in self.replicas.values():
            replica.is_primary = False
            replica.state = ReplicaState.IDLE

    def _post_consensus_processing(
        self,
        task: Dict,
        result: Dict,
        pre_prepare_msg,
    ):
        """
        共识完成后的后处理

        执行：
        1. 更新所有节点的信誉分数
        2. 分配激励奖励
        3. 同步信誉/权重到 Agent 对象
        4. 颁发新的信誉凭证
        """
        task_id = task.get("task_id", task.get("id", ""))
        leader_id = result.get("primary_id", "")
        answer = result.get("answer", "")

        # 收集本轮投票信息
        votes = []
        for replica in self.replicas.values():
            if replica.agent.id == leader_id:
                continue
            # 从消息日志中获取 PREPARE 消息
            seq = result.get("sequence_number", 0)
            if seq in replica.message_log.prepare:
                for prep_msg in replica.message_log.prepare[seq].values():
                    votes.append({
                        "voter_id": prep_msg.sender_id,
                        "decision": prep_msg.decision,
                        "confidence": prep_msg.confidence,
                    })

        # 获取正确答案（如果任务中有提供）
        correct_answer = task.get("answer", task.get("correct_answer", None))

        # === 1. 信誉更新 ===
        if self.reputation_system:
            print(f"\n[后处理] 更新信誉分数...")
            updates = self.reputation_system.update_after_consensus(
                task_id=task_id,
                leader_id=leader_id,
                leader_answer=answer,
                votes=votes,
                consensus_decision=result.get("decision", "Y"),
                correct_answer=correct_answer,
            )

            # 打印信誉变更
            for aid, u in updates.items():
                if abs(u.delta) > 0.001:
                    print(f"  {aid}: {u.old_reputation:.4f} -> {u.new_reputation:.4f} ({u.delta:+.4f}) [{u.reason}]")

            # 同步到 Agent 对象
            self.reputation_system.sync_to_agents(self.agents)

            # 颁发信誉凭证
            if self.did_registry:
                for agent in self.agents:
                    if agent.did:
                        rep = self.reputation_system.get_reputation(agent.id)
                        self.did_registry.issue_reputation_credential(
                            did=agent.did,
                            reputation_score=rep,
                            total_tasks=agent.tasks_participated,
                            success_rate=agent.tasks_success / max(1, agent.tasks_participated),
                        )

        # === 2. 激励分配 ===
        if self.incentive_system:
            print(f"\n[后处理] 分配激励奖励...")
            voter_ids = [v["voter_id"] for v in votes]
            rewards = self.incentive_system.distribute_consensus_rewards(
                task_id=task_id,
                leader_id=leader_id,
                voter_ids=voter_ids,
                success=result["success"],
                leader_answer=answer,
                correct_answer=correct_answer,
            )

        # === 3. 更新 Agent 任务统计 ===
        for agent in self.agents:
            agent.tasks_participated += 1
            if result["success"]:
                agent.tasks_success += 1

        # === 4. 记录行为日志 ===
        if self.behavior_log:
            for agent in self.agents:
                if agent.did:
                    self.behavior_log.record_consensus_result(
                        agent_id=agent.id,
                        did=agent.did,
                        task_id=task_id,
                        success=result["success"],
                        answer=answer,
                    )

    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            "consensus_count": self.consensus_count,
            "view_change_count": self.view_change_count,
            "total_nodes": self.total_nodes,
            "fault_tolerance": self.f,
            "total_messages": self.total_messages,
            "current_view": self.current_view,
            "success_rate": (
                self.consensus_count / (self.consensus_count + self.view_change_count)
                if (self.consensus_count + self.view_change_count) > 0
                else 0
            ),
        }


if __name__ == "__main__":
    # 测试完整PBFT
    print("=== Testing Complete PBFT ===")

    from agents import create_agents
    from network import Network
    from llm_new import LLMCaller

    # 创建Agent (5个节点，可以容忍1个故障节点)
    agents = create_agents(num_agents=5, malicious_ratio=0.2)

    # 创建网络
    network = Network(delay_range=(10, 50))

    # 注册节点
    for agent in agents:
        network.register(agent)

    # 创建LLM
    llm = LLMCaller(backend="mock", accuracy=0.9)

    # 设置LLM
    for agent in agents:
        agent.llm_caller = llm

    # 创建PBFT实例
    bft = BFT4Agent(agents=agents, network=network)

    # 运行共识
    task = {"content": "23 * 47 = ?", "type": "math"}
    result = bft.run(task)

    print(f"\n=== Result ===")
    print(f"Success: {result['success']}")
    print(f"Answer: {result.get('answer', 'N/A')}")

    # 统计信息
    stats = bft.get_stats()
    print(f"\n=== Statistics ===")
    for key, value in stats.items():
        print(f"{key}: {value}")
