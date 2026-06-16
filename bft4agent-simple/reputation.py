"""
信誉演化与加权投票系统

基于论文 4.2.2 节的信誉加权机制，实现：
1. 信誉分数的动态演化（贝叶斯更新 + 增减惩罚）
2. 加权投票权重计算
3. 信誉等级划分
4. 信誉与 DID 系统联动（信誉过低自动暂停身份）

信誉更新公式（来自论文）：
    R_i^(t+1) = R_i^(t) + alpha * Qual(O)     # 与多数一致的节点
    R_i^(t+1) = R_i^(t) * (1 - beta)           # 与多数不一致的节点（恶意嫌疑）
    R_i^(t+1) = R_i^(t)                        # 弃权/超时

投票权重：
    w_i = R_i / sum(R_j)  （归一化）
"""

import time
import math
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class ReputationLevel(Enum):
    """信誉等级"""
    EXCELLENT = "excellent"    # >= 0.9
    GOOD = "good"              # >= 0.7
    AVERAGE = "average"        # >= 0.5
    POOR = "poor"              # >= 0.3
    DANGEROUS = "dangerous"    # < 0.3


@dataclass
class ReputationUpdate:
    """单次信誉更新记录"""
    agent_id: str
    did: str
    old_reputation: float
    new_reputation: float
    delta: float
    reason: str
    task_id: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()


class ReputationSystem:
    """
    信誉系统管理器

    管理所有 Agent 的信誉分数，根据共识行为动态更新。
    与 DID 注册表联动：信誉过低时自动暂停身份。

    核心参数：
    - alpha: 奖励系数（诚实行为的增量）
    - beta: 惩罚系数（恶意行为的扣减比例）
    - decay_factor: 自然衰减因子（长时间不参与任务，信誉缓慢下降）
    - suspend_threshold: 暂停阈值（低于此值暂停 DID）
    - revoke_threshold: 吊销阈值（低于此值吊销 DID）
    """

    # 默认参数
    DEFAULT_ALPHA = 0.05           # 奖励增量
    DEFAULT_BETA = 0.3             # 惩罚扣减比例（惩罚 >> 奖励，严打恶意）
    DEFAULT_DECAY_FACTOR = 0.995   # 自然衰减因子（每轮乘以此值）
    DEFAULT_SUSPEND_THRESHOLD = 0.3   # 暂停阈值
    DEFAULT_REVOKE_THRESHOLD = 0.1    # 吊销阈值
    DEFAULT_INITIAL_REPUTATION = 1.0  # 初始信誉

    def __init__(
        self,
        did_registry=None,
        behavior_log=None,
        alpha: float = None,
        beta: float = None,
        decay_factor: float = None,
        suspend_threshold: float = None,
        revoke_threshold: float = None,
    ):
        """
        初始化信誉系统

        Args:
            did_registry: DID 注册表实例（用于联动暂停/吊销）
            behavior_log: 行为日志实例（用于记录信誉变更）
            alpha: 奖励系数
            beta: 惩罚系数
            decay_factor: 自然衰减因子
            suspend_threshold: 暂停阈值
            revoke_threshold: 吊销阈值
        """
        self.did_registry = did_registry
        self.behavior_log = behavior_log

        self.alpha = alpha if alpha is not None else self.DEFAULT_ALPHA
        self.beta = beta if beta is not None else self.DEFAULT_BETA
        self.decay_factor = decay_factor if decay_factor is not None else self.DEFAULT_DECAY_FACTOR
        self.suspend_threshold = suspend_threshold if suspend_threshold is not None else self.DEFAULT_SUSPEND_THRESHOLD
        self.revoke_threshold = revoke_threshold if revoke_threshold is not None else self.DEFAULT_REVOKE_THRESHOLD

        # 信誉记录 {agent_id: float}
        self._reputations: Dict[str, float] = {}
        # 更新历史
        self._update_history: List[ReputationUpdate] = []

        # 统计信息
        self.stats = {
            "total_updates": 0,
            "total_rewards": 0,
            "total_penalties": 0,
            "total_suspensions": 0,
            "total_revocations": 0,
        }

    def initialize(self, agents: List):
        """
        初始化所有 Agent 的信誉分数

        Args:
            agents: Agent 列表
        """
        for agent in agents:
            self._reputations[agent.id] = self.DEFAULT_INITIAL_REPUTATION
            agent.reputation = self.DEFAULT_INITIAL_REPUTATION

        print(f"[信誉系统] 初始化完成: {len(agents)} 个 Agent, 初始信誉={self.DEFAULT_INITIAL_REPUTATION}")

    def get_reputation(self, agent_id: str) -> float:
        """获取 Agent 的当前信誉"""
        return self._reputations.get(agent_id, self.DEFAULT_INITIAL_REPUTATION)

    def get_voting_weight(self, agent_id: str) -> float:
        """
        获取 Agent 的投票权重

        投票权重 = 信誉分数 / 所有活跃节点信誉总和
        只有 DID 活跃的节点才参与权重分配

        Args:
            agent_id: Agent ID

        Returns:
            归一化投票权重
        """
        return self.compute_all_weights().get(agent_id, 0.0)

    def compute_all_weights(self) -> Dict[str, float]:
        """
        计算所有 Agent 的归一化投票权重

        权重计算方式：
        1. 只计算 DID 活跃的节点
        2. 信誉低于暂停阈值的节点权重为 0
        3. w_i = R_i / sum(R_j for all active j)

        Returns:
            {agent_id: weight} 字典
        """
        active_reputations = {}
        for agent_id, rep in self._reputations.items():
            # 检查 DID 是否活跃
            if self.did_registry:
                did = self.did_registry.get_did(agent_id)
                if did:
                    valid, _ = self.did_registry.verify_identity(did)
                    if not valid:
                        continue  # DID 不活跃，跳过
            # 信誉过低也跳过
            if rep < self.suspend_threshold:
                continue
            active_reputations[agent_id] = rep

        total_reputation = sum(active_reputations.values())

        if total_reputation == 0:
            # 如果所有信誉都为 0，平均分配
            n = len(active_reputations)
            return {aid: 1.0 / n for aid in active_reputations} if n > 0 else {}

        return {aid: rep / total_reputation for aid, rep in active_reputations.items()}

    def update_after_consensus(
        self,
        task_id: str,
        leader_id: str,
        leader_answer: str,
        votes: List[Dict],
        consensus_decision: str,
        correct_answer: str = None,
    ) -> Dict[str, ReputationUpdate]:
        """
        共识完成后更新所有参与节点的信誉

        更新策略：
        1. 对于 Leader:
           - 如果提案被接受且答案正确: 奖励
           - 如果提案被接受但答案错误: 惩罚
           - 如果提案被拒绝: 轻微惩罚
        2. 对于 Backup 投票节点:
           - 投 Y 且最终共识正确: 奖励
           - 投 Y 但最终共识错误（被恶意误导）: 轻微惩罚
           - 投 N 且最终共识错误（正确识别恶意）: 奖励
           - 投 N 但最终共识正确（误杀）: 轻微惩罚
        3. 超时/未参与的节点: 自然衰减

        Args:
            task_id: 任务 ID
            leader_id: Leader Agent ID
            leader_answer: Leader 的提案答案
            votes: 投票列表 [{"voter_id": ..., "decision": Y/N, ...}]
            consensus_decision: 最终共识决策 ("Y" 或 "N")
            correct_answer: 正确答案（如果已知，用于精确评估）

        Returns:
            {agent_id: ReputationUpdate} 更新记录
        """
        updates = {}

        # 判断提案是否正确（如果有正确答案）
        is_proposal_correct = None
        if correct_answer is not None:
            is_proposal_correct = str(leader_answer).strip() == str(correct_answer).strip()

        # === 1. 更新 Leader 信誉 ===
        if consensus_decision == "Y":
            # 提案被接受
            if is_proposal_correct is True:
                # 答案正确，奖励 Leader
                update = self._apply_reward(
                    agent_id=leader_id,
                    task_id=task_id,
                    reason="提案正确且被接受",
                )
            elif is_proposal_correct is False:
                # 答案错误但被接受（可能因为恶意节点过多），严厉惩罚
                update = self._apply_penalty(
                    agent_id=leader_id,
                    task_id=task_id,
                    reason="提案错误却被接受",
                    penalty_multiplier=2.0,  # 加倍惩罚
                )
            else:
                # 无法判断正确性，给予轻微奖励
                update = self._apply_reward(
                    agent_id=leader_id,
                    task_id=task_id,
                    reason="提案被接受",
                    reward_multiplier=0.5,
                )
        else:
            # 提案被拒绝
            if is_proposal_correct is False:
                # 答案确实错误，Leader 只受轻微惩罚（系统正常运作）
                update = self._apply_penalty(
                    agent_id=leader_id,
                    task_id=task_id,
                    reason="提案错误被正确拒绝",
                    penalty_multiplier=0.5,
                )
            else:
                # 答案可能正确但被拒绝（可能有恶意投票），不惩罚 Leader
                update = self._neutral(
                    agent_id=leader_id,
                    task_id=task_id,
                    reason="提案被拒绝（可能被恶意投票）",
                )

        if update:
            updates[leader_id] = update

        # === 2. 更新 Backup 投票节点信誉 ===
        # 判断共识结果是否正确
        is_consensus_correct = None
        if is_proposal_correct is not None:
            if consensus_decision == "Y":
                is_consensus_correct = is_proposal_correct
            else:
                # 拒绝了提案
                is_consensus_correct = not is_proposal_correct

        voter_ids = set()
        for vote in votes:
            voter_id = vote.get("voter_id", "")
            decision = vote.get("decision", "N")
            voter_ids.add(voter_id)

            if voter_id == leader_id:
                continue  # 跳过 Leader

            if is_consensus_correct is not None:
                # 能判断正确性时
                if decision == "Y":
                    if is_proposal_correct:
                        # 投 Y 且答案正确：诚实投票
                        update = self._apply_reward(
                            agent_id=voter_id,
                            task_id=task_id,
                            reason="正确投Y（支持正确提案）",
                        )
                    else:
                        # 投 Y 但答案错误：可能是恶意或误判
                        update = self._apply_penalty(
                            agent_id=voter_id,
                            task_id=task_id,
                            reason="错误投Y（支持错误提案）",
                        )
                else:  # N
                    if not is_proposal_correct:
                        # 投 N 且答案确实错误：正确识别
                        update = self._apply_reward(
                            agent_id=voter_id,
                            task_id=task_id,
                            reason="正确投N（识别错误提案）",
                            reward_multiplier=1.5,  # 额外奖励发现错误
                        )
                    else:
                        # 投 N 但答案正确：误杀或恶意
                        update = self._apply_penalty(
                            agent_id=voter_id,
                            task_id=task_id,
                            reason="错误投N（拒绝正确提案）",
                        )
            else:
                # 无法判断正确性时，基于共识结果
                if consensus_decision == "Y":
                    # 多数接受
                    if decision == "Y":
                        update = self._apply_reward(
                            agent_id=voter_id,
                            task_id=task_id,
                            reason="与多数一致（Y）",
                            reward_multiplier=0.5,
                        )
                    else:
                        update = self._apply_penalty(
                            agent_id=voter_id,
                            task_id=task_id,
                            reason="与多数不一致（投N但共识Y）",
                            penalty_multiplier=0.5,
                        )
                else:
                    # 多数拒绝
                    if decision == "N":
                        update = self._apply_reward(
                            agent_id=voter_id,
                            task_id=task_id,
                            reason="与多数一致（N）",
                            reward_multiplier=0.5,
                        )
                    else:
                        update = self._apply_penalty(
                            agent_id=voter_id,
                            task_id=task_id,
                            reason="与多数不一致（投Y但共识N）",
                            penalty_multiplier=0.5,
                        )

            if update:
                updates[voter_id] = update

        # === 3. 对未参与投票的节点应用自然衰减 ===
        for agent_id in self._reputations:
            if agent_id not in voter_ids and agent_id != leader_id:
                update = self._apply_decay(
                    agent_id=agent_id,
                    task_id=task_id,
                )
                if update:
                    updates[agent_id] = update

        return updates

    # ========== 信誉操作方法 ==========

    def _apply_reward(
        self,
        agent_id: str,
        task_id: str = "",
        reason: str = "",
        reward_multiplier: float = 1.0,
    ) -> Optional[ReputationUpdate]:
        """应用奖励"""
        old_rep = self._reputations.get(agent_id, self.DEFAULT_INITIAL_REPUTATION)
        delta = self.alpha * reward_multiplier
        new_rep = min(1.0, old_rep + delta)  # 上限 1.0

        update = ReputationUpdate(
            agent_id=agent_id,
            did="",  # 将在同步时填充
            old_reputation=old_rep,
            new_reputation=new_rep,
            delta=delta,
            reason=reason,
            task_id=task_id,
        )

        self._reputations[agent_id] = new_rep
        self._update_history.append(update)
        self.stats["total_updates"] += 1
        self.stats["total_rewards"] += 1

        return update

    def _apply_penalty(
        self,
        agent_id: str,
        task_id: str = "",
        reason: str = "",
        penalty_multiplier: float = 1.0,
    ) -> Optional[ReputationUpdate]:
        """应用惩罚"""
        old_rep = self._reputations.get(agent_id, self.DEFAULT_INITIAL_REPUTATION)
        # 乘法惩罚：new = old * (1 - beta * multiplier)
        factor = max(0.0, 1.0 - self.beta * penalty_multiplier)
        new_rep = old_rep * factor
        delta = new_rep - old_rep  # 负值

        update = ReputationUpdate(
            agent_id=agent_id,
            did="",
            old_reputation=old_rep,
            new_reputation=new_rep,
            delta=delta,
            reason=reason,
            task_id=task_id,
        )

        self._reputations[agent_id] = new_rep
        self._update_history.append(update)
        self.stats["total_updates"] += 1
        self.stats["total_penalties"] += 1

        # 检查是否需要暂停或吊销 DID
        self._check_did_status(agent_id, new_rep)

        return update

    def _apply_decay(
        self,
        agent_id: str,
        task_id: str = "",
    ) -> Optional[ReputationUpdate]:
        """应用自然衰减"""
        old_rep = self._reputations.get(agent_id, self.DEFAULT_INITIAL_REPUTATION)
        new_rep = old_rep * self.decay_factor
        delta = new_rep - old_rep

        if abs(delta) < 1e-6:
            return None

        update = ReputationUpdate(
            agent_id=agent_id,
            did="",
            old_reputation=old_rep,
            new_reputation=new_rep,
            delta=delta,
            reason="自然衰减（未参与任务）",
            task_id=task_id,
        )

        self._reputations[agent_id] = new_rep
        self._update_history.append(update)

        return update

    def _neutral(
        self,
        agent_id: str,
        task_id: str = "",
        reason: str = "",
    ) -> ReputationUpdate:
        """不增不减，仅记录"""
        old_rep = self._reputations.get(agent_id, self.DEFAULT_INITIAL_REPUTATION)
        return ReputationUpdate(
            agent_id=agent_id,
            did="",
            old_reputation=old_rep,
            new_reputation=old_rep,
            delta=0.0,
            reason=reason,
            task_id=task_id,
        )

    def _check_did_status(self, agent_id: str, reputation: float):
        """检查信誉变化后是否需要调整 DID 状态"""
        if not self.did_registry:
            return

        did = self.did_registry.get_did(agent_id)
        if not did:
            return

        if reputation < self.revoke_threshold:
            # 吊销 DID
            success, slashed = self.did_registry.revoke(did, reason=f"信誉过低 ({reputation:.3f} < {self.revoke_threshold})")
            if success:
                self.stats["total_revocations"] += 1
                print(f"[信誉-DID联动] 吊销 {did}: 信誉={reputation:.3f}, 罚没={slashed:.2f}")

        elif reputation < self.suspend_threshold:
            # 暂停 DID
            success = self.did_registry.suspend(did, reason=f"信誉过低 ({reputation:.3f} < {self.suspend_threshold})")
            if success:
                self.stats["total_suspensions"] += 1
                print(f"[信誉-DID联动] 暂停 {did}: 信誉={reputation:.3f}")

    # ========== 同步到 Agent ==========

    def sync_to_agents(self, agents: List):
        """
        将信誉分数同步到 Agent 对象

        同时更新投票权重

        Args:
            agents: Agent 列表
        """
        weights = self.compute_all_weights()

        for agent in agents:
            # 同步信誉分数
            if agent.id in self._reputations:
                agent.reputation = self._reputations[agent.id]

            # 同步投票权重
            agent.voting_weight = weights.get(agent.id, 0.0)

    # ========== 查询 ==========

    @staticmethod
    def get_reputation_level(score: float) -> ReputationLevel:
        """获取信誉等级"""
        if score >= 0.9:
            return ReputationLevel.EXCELLENT
        elif score >= 0.7:
            return ReputationLevel.GOOD
        elif score >= 0.5:
            return ReputationLevel.AVERAGE
        elif score >= 0.3:
            return ReputationLevel.POOR
        else:
            return ReputationLevel.DANGEROUS

    def get_all_reputations(self) -> Dict[str, float]:
        """获取所有 Agent 的信誉分数"""
        return dict(self._reputations)

    def get_update_history(self, agent_id: str = None, limit: int = 100) -> List[Dict]:
        """
        获取信誉更新历史

        Args:
            agent_id: 可选，按 Agent 过滤
            limit: 返回条数限制

        Returns:
            更新记录列表
        """
        history = self._update_history
        if agent_id:
            history = [u for u in history if u.agent_id == agent_id]

        return [
            {
                "agent_id": u.agent_id,
                "old_rep": u.old_reputation,
                "new_rep": u.new_reputation,
                "delta": u.delta,
                "reason": u.reason,
                "task_id": u.task_id,
                "timestamp": u.timestamp,
            }
            for u in history[-limit:]
        ]

    def get_stats(self) -> Dict:
        """获取信誉系统统计"""
        reputations = list(self._reputations.values())
        return {
            **self.stats,
            "total_agents": len(self._reputations),
            "avg_reputation": sum(reputations) / len(reputations) if reputations else 0,
            "min_reputation": min(reputations) if reputations else 0,
            "max_reputation": max(reputations) if reputations else 0,
            "alpha": self.alpha,
            "beta": self.beta,
            "suspend_threshold": self.suspend_threshold,
            "revoke_threshold": self.revoke_threshold,
        }


# ========== 快速测试 ==========

if __name__ == "__main__":
    print("=" * 60)
    print("  信誉演化系统测试")
    print("=" * 60)

    from did_registry import DIDRegistry

    # 创建 DID 注册表
    registry = DIDRegistry(min_stake=100.0)

    # 创建信誉系统
    rep_system = ReputationSystem(
        did_registry=registry,
        alpha=0.05,
        beta=0.3,
    )

    # 模拟 5 个 Agent
    reputations = {}
    for i in range(1, 6):
        agent_id = f"agent_{i}"
        registry.register(agent_id, stake_amount=200.0, specialty="math")
        reputations[agent_id] = 1.0

    rep_system._reputations = reputations

    # 模拟第 1 轮共识
    print("\n--- 第 1 轮共识 ---")
    updates = rep_system.update_after_consensus(
        task_id="task_001",
        leader_id="agent_1",
        leader_answer="1081",
        votes=[
            {"voter_id": "agent_2", "decision": "Y"},
            {"voter_id": "agent_3", "decision": "Y"},
            {"voter_id": "agent_4", "decision": "N"},  # 恶意投 N
            {"voter_id": "agent_5", "decision": "Y"},
        ],
        consensus_decision="Y",
        correct_answer="1081",
    )

    print("\n信誉更新:")
    for aid, u in updates.items():
        print(f"  {aid}: {u.old_reputation:.4f} -> {u.new_reputation:.4f} ({u.delta:+.4f}) [{u.reason}]")

    # 查看权重
    print("\n投票权重:")
    weights = rep_system.compute_all_weights()
    for aid, w in weights.items():
        print(f"  {aid}: weight={w:.4f}, rep={rep_system.get_reputation(aid):.4f}")

    # 模拟多轮，让 agent_4 信誉持续下降
    print("\n--- 模拟恶意节点连续 5 轮 ---")
    for round_num in range(2, 7):
        print(f"\n  第 {round_num} 轮:")
        updates = rep_system.update_after_consensus(
            task_id=f"task_00{round_num}",
            leader_id="agent_2",
            leader_answer="42",
            votes=[
                {"voter_id": "agent_1", "decision": "Y"},
                {"voter_id": "agent_3", "decision": "Y"},
                {"voter_id": "agent_4", "decision": "N"},  # 持续恶意
                {"voter_id": "agent_5", "decision": "Y"},
            ],
            consensus_decision="Y",
            correct_answer="42",
        )
        rep4 = rep_system.get_reputation("agent_4")
        print(f"  agent_4 信誉: {rep4:.4f} (level: {rep_system.get_reputation_level(rep4).value})")

    # 最终统计
    print("\n--- 最终统计 ---")
    stats = rep_system.get_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")

    # DID 状态
    print("\n--- DID 状态 ---")
    for i in range(1, 6):
        aid = f"agent_{i}"
        did = registry.get_did(aid)
        doc = registry.resolve(did) if did else None
        status = doc.status.value if doc else "N/A"
        rep = rep_system.get_reputation(aid)
        print(f"  {aid}: rep={rep:.4f}, did_status={status}")
