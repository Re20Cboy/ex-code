"""
Agent 行为追踪日志系统

记录每个 Agent 在共识过程中的完整行为轨迹，实现：
1. 行为事件记录（提案、投票、掉线、超时等）
2. 行为模式分析（识别恶意模式）
3. 行为报告生成（用于信誉评估和实验分析）
4. 链上存证模拟（行为不可篡改记录）

行为事件类型：
- PROPOSE: Leader 生成提案
- VOTE_Y: 投赞成票
- VOTE_N: 投反对票
- TIMEOUT: 响应超时
- OFFLINE: 节点离线
- VIEW_CHANGE: 参与视图切换
- MALICIOUS_DETECT: 检测到恶意行为
- CONSENSUS_SUCCESS: 参与共识成功
- CONSENSUS_FAIL: 参与共识失败
"""

import time
import json
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class BehaviorEventType(Enum):
    """行为事件类型"""
    PROPOSE = "propose"                 # Leader 生成提案
    VOTE_Y = "vote_y"                   # 投赞成票
    VOTE_N = "vote_n"                   # 投反对票
    TIMEOUT = "timeout"                 # 响应超时
    OFFLINE = "offline"                 # 节点离线
    VIEW_CHANGE = "view_change"         # 视图切换
    MALICIOUS_DETECT = "malicious_detect"  # 恶意行为被检测
    CONSENSUS_SUCCESS = "consensus_success"  # 共识成功
    CONSENSUS_FAIL = "consensus_fail"       # 共识失败
    STAKE_SLASH = "stake_slash"             # 质押被罚没
    DID_SUSPEND = "did_suspend"             # DID 被暂停
    DID_REVOKE = "did_revoke"               # DID 被吊销


@dataclass
class BehaviorEvent:
    """
    单条行为事件记录

    每个事件包含：
    - 谁（agent_id + did）
    - 何时（timestamp）
    - 做了什么（event_type）
    - 在什么上下文中（task_id, view, sequence_number）
    - 结果是什么（details）
    - 可验证的存证哈希（event_hash）
    """
    event_id: str
    agent_id: str
    did: str
    event_type: BehaviorEventType
    timestamp: float
    task_id: str = ""
    view: int = 0
    sequence_number: int = 0
    details: Dict = field(default_factory=dict)
    event_hash: str = ""

    def __post_init__(self):
        """计算事件哈希（防篡改）"""
        if not self.event_hash:
            self.event_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """计算事件哈希"""
        content = (
            f"{self.agent_id}:{self.did}:{self.event_type.value}:"
            f"{self.timestamp}:{self.task_id}:{self.view}:"
            f"{self.sequence_number}:{json.dumps(self.details, sort_keys=True)}"
        )
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict:
        return {
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "did": self.did,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "task_id": self.task_id,
            "view": self.view,
            "sequence_number": self.sequence_number,
            "details": self.details,
            "event_hash": self.event_hash,
        }

    def verify_integrity(self) -> bool:
        """验证事件完整性（防篡改检查）"""
        return self.event_hash == self._compute_hash()


class BehaviorLog:
    """
    行为追踪日志管理器

    核心功能：
    1. 记录所有 Agent 的行为事件
    2. 按 Agent / 任务 / 时间范围查询行为
    3. 分析行为模式（恶意检测）
    4. 生成行为报告
    5. 计算行为指标（参与率、正确率、恶意嫌疑度等）
    """

    def __init__(self):
        # 所有事件的全局日志（按时间排序）
        self._events: List[BehaviorEvent] = []
        # 按 agent_id 索引的事件列表
        self._agent_events: Dict[str, List[BehaviorEvent]] = defaultdict(list)
        # 按 task_id 索引的事件列表
        self._task_events: Dict[str, List[BehaviorEvent]] = defaultdict(list)
        # 事件计数器（用于生成 event_id）
        self._event_counter = 0
        # 前一个事件的哈希（用于构建事件链，防篡改）
        self._prev_hash = "genesis"

    # ========== 事件记录 ==========

    def record(
        self,
        agent_id: str,
        did: str,
        event_type: BehaviorEventType,
        task_id: str = "",
        view: int = 0,
        sequence_number: int = 0,
        details: Dict = None,
    ) -> BehaviorEvent:
        """
        记录一条行为事件

        Args:
            agent_id: Agent ID
            did: Agent 的 DID
            event_type: 事件类型
            task_id: 任务 ID
            view: 视图号
            sequence_number: 序列号
            details: 附加详情

        Returns:
            记录的事件
        """
        self._event_counter += 1
        event_id = f"evt_{self._event_counter:06d}"

        # 构建详情字典，包含前一个事件的哈希（形成事件链）
        enriched_details = details or {}
        enriched_details["prev_hash"] = self._prev_hash

        event = BehaviorEvent(
            event_id=event_id,
            agent_id=agent_id,
            did=did,
            event_type=event_type,
            timestamp=time.time(),
            task_id=task_id,
            view=view,
            sequence_number=sequence_number,
            details=enriched_details,
        )

        # 存储事件
        self._events.append(event)
        self._agent_events[agent_id].append(event)
        if task_id:
            self._task_events[task_id].append(event)

        # 更新链头
        self._prev_hash = event.event_hash

        return event

    def record_propose(
        self, agent_id: str, did: str,
        task_id: str, view: int, seq: int,
        answer: str, confidence: float,
        is_correct: bool = None,
    ) -> BehaviorEvent:
        """
        记录提案行为（快捷方法）

        Args:
            agent_id: Agent ID
            did: DID
            task_id: 任务 ID
            view: 视图号
            seq: 序列号
            answer: 提案的答案
            confidence: 置信度
            is_correct: 答案是否正确（实验评估时可知）

        Returns:
            记录的事件
        """
        details = {
            "answer": str(answer),
            "confidence": confidence,
        }
        if is_correct is not None:
            details["is_correct"] = is_correct

        return self.record(
            agent_id=agent_id,
            did=did,
            event_type=BehaviorEventType.PROPOSE,
            task_id=task_id,
            view=view,
            sequence_number=seq,
            details=details,
        )

    def record_vote(
        self, agent_id: str, did: str,
        task_id: str, view: int, seq: int,
        decision: str, confidence: float = 0.0,
        reason: str = "",
        is_honest_vote: bool = None,
    ) -> BehaviorEvent:
        """
        记录投票行为（快捷方法）

        Args:
            agent_id: Agent ID
            did: DID
            task_id: 任务 ID
            view: 视图号
            seq: 序列号
            decision: 投票决策 (Y/N)
            confidence: 置信度
            reason: 投票理由
            is_honest_vote: 投票是否诚实（实验评估时可知）

        Returns:
            记录的事件
        """
        event_type = BehaviorEventType.VOTE_Y if decision == "Y" else BehaviorEventType.VOTE_N
        details = {
            "decision": decision,
            "confidence": confidence,
            "reason": reason,
        }
        if is_honest_vote is not None:
            details["is_honest_vote"] = is_honest_vote

        return self.record(
            agent_id=agent_id,
            did=did,
            event_type=event_type,
            task_id=task_id,
            view=view,
            sequence_number=seq,
            details=details,
        )

    def record_timeout(
        self, agent_id: str, did: str,
        task_id: str, view: int,
        phase: str = "",
    ) -> BehaviorEvent:
        """记录超时事件"""
        return self.record(
            agent_id=agent_id,
            did=did,
            event_type=BehaviorEventType.TIMEOUT,
            task_id=task_id,
            view=view,
            details={"phase": phase},
        )

    def record_offline(
        self, agent_id: str, did: str,
        duration: float = 0.0,
    ) -> BehaviorEvent:
        """记录离线事件"""
        return self.record(
            agent_id=agent_id,
            did=did,
            event_type=BehaviorEventType.OFFLINE,
            details={"duration": duration},
        )

    def record_consensus_result(
        self, agent_id: str, did: str,
        task_id: str, success: bool,
        answer: str = "",
    ) -> BehaviorEvent:
        """记录共识结果"""
        event_type = BehaviorEventType.CONSENSUS_SUCCESS if success else BehaviorEventType.CONSENSUS_FAIL
        return self.record(
            agent_id=agent_id,
            did=did,
            event_type=event_type,
            task_id=task_id,
            details={"answer": str(answer)},
        )

    # ========== 查询 ==========

    def get_agent_events(
        self,
        agent_id: str,
        event_type: BehaviorEventType = None,
    ) -> List[BehaviorEvent]:
        """
        获取指定 Agent 的事件列表

        Args:
            agent_id: Agent ID
            event_type: 可选，按事件类型过滤

        Returns:
            事件列表
        """
        events = self._agent_events.get(agent_id, [])
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events

    def get_task_events(
        self,
        task_id: str,
        agent_id: str = None,
    ) -> List[BehaviorEvent]:
        """
        获取指定任务的事件列表

        Args:
            task_id: 任务 ID
            agent_id: 可选，按 Agent 过滤

        Returns:
            事件列表
        """
        events = self._task_events.get(task_id, [])
        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]
        return events

    def get_events_in_range(
        self,
        start_time: float,
        end_time: float,
        agent_id: str = None,
    ) -> List[BehaviorEvent]:
        """
        获取时间范围内的事件

        Args:
            start_time: 开始时间
            end_time: 结束时间
            agent_id: 可选，按 Agent 过滤

        Returns:
            事件列表
        """
        events = [
            e for e in self._events
            if start_time <= e.timestamp <= end_time
        ]
        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]
        return events

    def get_all_events(self) -> List[BehaviorEvent]:
        """获取所有事件"""
        return list(self._events)

    # ========== 行为分析 ==========

    def get_agent_stats(self, agent_id: str) -> Dict:
        """
        获取指定 Agent 的行为统计

        Returns:
            统计字典，包含：
            - total_events: 总事件数
            - propose_count: 提案次数
            - vote_y_count: Y 票数
            - vote_n_count: N 票数
            - timeout_count: 超时次数
            - offline_count: 离线次数
            - consensus_success_count: 参与共识成功次数
            - consensus_fail_count: 参与共识失败次数
            - participation_rate: 参与率
            - agree_rate: 赞成率（Y / 总投票数）
        """
        events = self._agent_events.get(agent_id, [])

        stats = {
            "agent_id": agent_id,
            "total_events": len(events),
            "propose_count": 0,
            "vote_y_count": 0,
            "vote_n_count": 0,
            "timeout_count": 0,
            "offline_count": 0,
            "consensus_success_count": 0,
            "consensus_fail_count": 0,
            "malicious_detect_count": 0,
            "stake_slash_count": 0,
        }

        for event in events:
            if event.event_type == BehaviorEventType.PROPOSE:
                stats["propose_count"] += 1
            elif event.event_type == BehaviorEventType.VOTE_Y:
                stats["vote_y_count"] += 1
            elif event.event_type == BehaviorEventType.VOTE_N:
                stats["vote_n_count"] += 1
            elif event.event_type == BehaviorEventType.TIMEOUT:
                stats["timeout_count"] += 1
            elif event.event_type == BehaviorEventType.OFFLINE:
                stats["offline_count"] += 1
            elif event.event_type == BehaviorEventType.CONSENSUS_SUCCESS:
                stats["consensus_success_count"] += 1
            elif event.event_type == BehaviorEventType.CONSENSUS_FAIL:
                stats["consensus_fail_count"] += 1
            elif event.event_type == BehaviorEventType.MALICIOUS_DETECT:
                stats["malicious_detect_count"] += 1
            elif event.event_type == BehaviorEventType.STAKE_SLASH:
                stats["stake_slash_count"] += 1

        # 计算派生指标
        total_votes = stats["vote_y_count"] + stats["vote_n_count"]
        stats["agree_rate"] = (
            stats["vote_y_count"] / total_votes if total_votes > 0 else 0.0
        )

        total_consensus = stats["consensus_success_count"] + stats["consensus_fail_count"]
        stats["consensus_success_rate"] = (
            stats["consensus_success_count"] / total_consensus if total_consensus > 0 else 0.0
        )

        return stats

    def detect_suspicious_patterns(self, agent_id: str) -> Dict:
        """
        检测可疑行为模式

        检测模式：
        1. 持续反对：几乎对所有提案投 N
        2. 总是支持恶意：对恶意提案投 Y
        3. 频繁超时：经常不响应
        4. 频繁离线：经常掉线
        5. 矛盾投票：对类似提案给出不一致的投票

        Args:
            agent_id: Agent ID

        Returns:
            检测结果字典
        """
        stats = self.get_agent_stats(agent_id)
        total_votes = stats["vote_y_count"] + stats["vote_n_count"]

        patterns = {
            "agent_id": agent_id,
            "suspicions": [],
            "suspicion_score": 0.0,  # 0.0-1.0，越高越可疑
        }

        # 模式1: 持续反对（N 票比例 > 80%）
        if total_votes > 3 and stats["vote_n_count"] / total_votes > 0.8:
            patterns["suspicions"].append({
                "type": "persistant_opposition",
                "description": f"持续反对: N票占比 {stats['vote_n_count']}/{total_votes} = {stats['vote_n_count']/total_votes:.1%}",
                "severity": "high",
            })
            patterns["suspicion_score"] += 0.4

        # 模式2: 频繁超时（超时次数 > 总事件数 * 30%）
        if stats["total_events"] > 5:
            timeout_rate = stats["timeout_count"] / stats["total_events"]
            if timeout_rate > 0.3:
                patterns["suspicions"].append({
                    "type": "frequent_timeout",
                    "description": f"频繁超时: {stats['timeout_count']}次, 占比 {timeout_rate:.1%}",
                    "severity": "medium",
                })
                patterns["suspicion_score"] += 0.2

        # 模式3: 频繁离线
        if stats["offline_count"] > 2:
            patterns["suspicions"].append({
                "type": "frequent_offline",
                "description": f"频繁离线: {stats['offline_count']}次",
                "severity": "medium",
            })
            patterns["suspicion_score"] += 0.2

        # 模式4: 已被检测到恶意行为
        if stats["malicious_detect_count"] > 0:
            patterns["suspicions"].append({
                "type": "confirmed_malicious",
                "description": f"已被检测到恶意行为: {stats['malicious_detect_count']}次",
                "severity": "critical",
            })
            patterns["suspicion_score"] += 0.5

        # 限制可疑分数在 [0, 1] 范围
        patterns["suspicion_score"] = min(1.0, patterns["suspicion_score"])

        return patterns

    # ========== 报告生成 ==========

    def generate_agent_report(self, agent_id: str) -> Dict:
        """
        生成指定 Agent 的完整行为报告

        Args:
            agent_id: Agent ID

        Returns:
            行为报告字典
        """
        stats = self.get_agent_stats(agent_id)
        patterns = self.detect_suspicious_patterns(agent_id)
        events = self.get_agent_events(agent_id)

        return {
            "agent_id": agent_id,
            "summary": stats,
            "suspicious_patterns": patterns,
            "recent_events": [e.to_dict() for e in events[-10:]],  # 最近10条
            "event_count": len(events),
        }

    def generate_task_report(self, task_id: str) -> Dict:
        """
        生成指定任务的行为报告

        Args:
            task_id: 任务 ID

        Returns:
            任务行为报告
        """
        events = self._task_events.get(task_id, [])

        # 按 agent 分组
        agent_summary = defaultdict(lambda: {"propose": 0, "vote_y": 0, "vote_n": 0, "timeout": 0})
        for event in events:
            if event.event_type == BehaviorEventType.PROPOSE:
                agent_summary[event.agent_id]["propose"] += 1
            elif event.event_type == BehaviorEventType.VOTE_Y:
                agent_summary[event.agent_id]["vote_y"] += 1
            elif event.event_type == BehaviorEventType.VOTE_N:
                agent_summary[event.agent_id]["vote_n"] += 1
            elif event.event_type == BehaviorEventType.TIMEOUT:
                agent_summary[event.agent_id]["timeout"] += 1

        return {
            "task_id": task_id,
            "total_events": len(events),
            "agent_summary": dict(agent_summary),
            "events": [e.to_dict() for e in events],
        }

    def generate_full_report(self) -> Dict:
        """
        生成全局行为报告（包含所有 Agent 的统计）

        Returns:
            全局行为报告
        """
        all_agents = list(self._agent_events.keys())
        agent_reports = {
            agent_id: self.generate_agent_report(agent_id)
            for agent_id in all_agents
        }

        return {
            "total_events": len(self._events),
            "total_agents": len(all_agents),
            "agent_reports": agent_reports,
            "global_stats": {
                "total_proposes": sum(r["summary"]["propose_count"] for r in agent_reports.values()),
                "total_vote_y": sum(r["summary"]["vote_y_count"] for r in agent_reports.values()),
                "total_vote_n": sum(r["summary"]["vote_n_count"] for r in agent_reports.values()),
                "total_timeouts": sum(r["summary"]["timeout_count"] for r in agent_reports.values()),
                "total_offlines": sum(r["summary"]["offline_count"] for r in agent_reports.values()),
            },
        }

    # ========== 链上存证模拟 ==========

    def compute_log_hash(self) -> str:
        """
        计算整个日志的默克尔根哈希（模拟链上存证）

        将所有事件的哈希两两配对，逐层计算直到得到根哈希。
        这模拟了区块链中将交易打包成 Merkle Tree 的过程。

        Returns:
            根哈希值
        """
        if not self._events:
            return hashlib.sha256(b"empty").hexdigest()

        # 获取所有事件哈希
        hashes = [e.event_hash for e in self._events]

        # 构建 Merkle Tree
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])  # 补齐为偶数

            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = f"{hashes[i]}{hashes[i+1]}"
                new_hashes.append(hashlib.sha256(combined.encode()).hexdigest()[:16])

            hashes = new_hashes

        return hashes[0]

    def verify_log_integrity(self) -> bool:
        """
        验证日志完整性（检查是否有事件被篡改）

        Returns:
            日志是否完整
        """
        for event in self._events:
            if not event.verify_integrity():
                return False
        return True

    # ========== 导出 ==========

    def export_events(self) -> List[Dict]:
        """导出所有事件为字典列表"""
        return [e.to_dict() for e in self._events]

    def get_stats(self) -> Dict:
        """获取日志系统统计信息"""
        return {
            "total_events": len(self._events),
            "total_agents": len(self._agent_events),
            "total_tasks": len(self._task_events),
            "log_hash": self.compute_log_hash(),
            "integrity_verified": self.verify_log_integrity(),
        }


# ========== 快速测试 ==========

if __name__ == "__main__":
    print("=" * 60)
    print("  行为追踪日志系统测试")
    print("=" * 60)

    log = BehaviorLog()

    # 模拟一轮共识的行为记录
    agent_did = "did:bft4agent:agent_1"

    # Agent 1 作为 Leader 提案
    log.record_propose(
        agent_id="agent_1", did=agent_did,
        task_id="task_001", view=0, seq=1,
        answer="1081", confidence=0.95,
    )

    # Agent 2 投 Y
    log.record_vote(
        agent_id="agent_2", did="did:bft4agent:agent_2",
        task_id="task_001", view=0, seq=1,
        decision="Y", confidence=0.9, reason="计算正确",
    )

    # Agent 3 投 N（恶意）
    log.record_vote(
        agent_id="agent_3", did="did:bft4agent:agent_3",
        task_id="task_001", view=0, seq=1,
        decision="N", confidence=0.95, reason="反对",
        is_honest_vote=False,
    )

    # Agent 4 超时
    log.record_timeout(
        agent_id="agent_4", did="did:bft4agent:agent_4",
        task_id="task_001", view=0, phase="prepare",
    )

    # 共识成功
    for aid in ["agent_1", "agent_2"]:
        log.record_consensus_result(
            agent_id=aid, did=f"did:bft4agent:{aid}",
            task_id="task_001", success=True, answer="1081",
        )

    # 打印统计
    print("\n--- Agent 统计 ---")
    for aid in ["agent_1", "agent_2", "agent_3", "agent_4"]:
        stats = log.get_agent_stats(aid)
        print(f"\n  {aid}:")
        for k, v in stats.items():
            print(f"    {k}: {v}")

    # 可疑行为检测
    print("\n--- 可疑行为检测 ---")
    for aid in ["agent_1", "agent_3", "agent_4"]:
        patterns = log.detect_suspicious_patterns(aid)
        print(f"\n  {aid}: suspicion_score={patterns['suspicion_score']:.2f}")
        for s in patterns["suspicions"]:
            print(f"    [{s['severity']}] {s['description']}")

    # 日志完整性
    print(f"\n--- 日志完整性 ---")
    print(f"  总事件数: {len(log.get_all_events())}")
    print(f"  日志哈希: {log.compute_log_hash()}")
    print(f"  完整性验证: {log.verify_log_integrity()}")