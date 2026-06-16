"""
激励层：奖惩与贡献分配系统

实现基于区块链智能合约模拟的激励机制：
1. 共识成功后的奖励分配（按贡献度）
2. 恶意行为的惩罚（质押罚没）
3. 掉线/超时的惩罚（轻量级）
4. 激励池管理（总奖金池、分配记录）
5. 贡献度量化（基于角色、信誉、参与度）

激励设计原则：
- 奖励诚实参与 > 惩罚恶意行为
- 贡献度与奖励挂钩（Leader 贡献 > Backup）
- 长期信誉累积带来复利效应
- 惩罚力度与恶意程度正相关
"""

import time
import math
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class RewardType(Enum):
    """奖励类型"""
    CONSENSUS_PROPOSAL = "consensus_proposal"    # Leader 成功提案奖励
    CONSENSUS_VALIDATION = "consensus_validation"  # Backup 正确验证奖励
    ACCURACY_BONUS = "accuracy_bonus"              # 准确率加成
    REPUTATION_BONUS = "reputation_bonus"          # 信誉加成
    LONGEVITY_BONUS = "longevity_bonus"            # 长期参与奖励


class PenaltyType(Enum):
    """惩罚类型"""
    MALICIOUS_PROPOSAL = "malicious_proposal"      # 恶意提案
    MALICIOUS_VOTE = "malicious_vote"              # 恶意投票
    TIMEOUT = "timeout"                            # 超时
    OFFLINE = "offline"                            # 离线
    LOW_REPUTATION = "low_reputation"              # 信誉过低
    SYBIL_ATTACK = "sybil_attack"                  # 女巫攻击


@dataclass
class IncentiveRecord:
    """激励记录"""
    record_id: str
    agent_id: str
    did: str
    record_type: str  # "reward" 或 "penalty"
    amount: float
    reason: str
    task_id: str = ""
    timestamp: float = 0.0
    details: Dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()


class IncentiveSystem:
    """
    激励系统管理器

    管理整个经济模型的激励分配：
    - 任务成功时：从激励池中分配奖励
    - 恶意行为时：罚没质押并注入激励池
    - 掉线/超时时：轻量级惩罚

    经济模型：
    - 初始激励池: initial_pool
    - 每轮任务奖励: base_reward * 参与者数量
    - 惩罚罚没: 按比例扣除质押
    """

    # 奖励参数
    BASE_PROPOSAL_REWARD = 10.0      # Leader 基础提案奖励
    BASE_VALIDATION_REWARD = 5.0     # Backup 基础验证奖励
    ACCURACY_BONUS_RATE = 0.2        # 准确率加成比例
    REPUTATION_BONUS_RATE = 0.1      # 信誉加成比例
    LONGEVITY_BONUS_THRESHOLD = 10   # 长期参与阈值（任务数）
    LONGEVITY_BONUS_RATE = 0.15      # 长期参与加成比例

    # 惩罚参数
    MALICIOUS_PROPOSAL_PENALTY = 50.0     # 恶意提案罚金
    MALICIOUS_VOTE_PENALTY = 30.0         # 恶意投票罚金
    TIMEOUT_PENALTY = 5.0                 # 超时罚金
    OFFLINE_PENALTY = 10.0                # 离线罚金

    def __init__(
        self,
        did_registry=None,
        reputation_system=None,
        behavior_log=None,
        initial_pool: float = 10000.0,
    ):
        """
        初始化激励系统

        Args:
            did_registry: DID 注册表
            reputation_system: 信誉系统
            behavior_log: 行为日志
            initial_pool: 初始激励池金额
        """
        self.did_registry = did_registry
        self.reputation_system = reputation_system
        self.behavior_log = behavior_log

        # 激励池
        self.incentive_pool = initial_pool
        self.initial_pool = initial_pool

        # 记录
        self._records: List[IncentiveRecord] = []
        self._record_counter = 0

        # Agent 账户余额 {agent_id: float}
        self._balances: Dict[str, float] = {}

        # 统计
        self.stats = {
            "total_rewards_distributed": 0.0,
            "total_penalties_collected": 0.0,
            "total_reward_count": 0,
            "total_penalty_count": 0,
        }

    # ========== 奖励分配 ==========

    def distribute_consensus_rewards(
        self,
        task_id: str,
        leader_id: str,
        voter_ids: List[str],
        success: bool,
        leader_answer: str = "",
        correct_answer: str = None,
    ) -> Dict[str, float]:
        """
        共识完成后分配奖励

        奖励计算：
        1. Leader 奖励 = BASE_PROPOSAL_REWARD * 信誉加成 * 准确率加成
        2. Backup 奖励 = BASE_VALIDATION_REWARD * 信誉加成
        3. 每个参与者还有长期参与加成

        Args:
            task_id: 任务 ID
            leader_id: Leader Agent ID
            voter_ids: 参与投票的 Agent ID 列表
            success: 共识是否成功
            leader_answer: Leader 的答案
            correct_answer: 正确答案（可选）

        Returns:
            {agent_id: reward_amount} 奖励分配
        """
        if not success:
            return {}

        rewards = {}

        # === Leader 奖励 ===
        leader_reward = self.BASE_PROPOSAL_REWARD

        # 准确率加成
        if correct_answer and leader_answer:
            if str(leader_answer).strip() == str(correct_answer).strip():
                leader_reward *= (1 + self.ACCURACY_BONUS_RATE)

        # 信誉加成
        if self.reputation_system:
            rep = self.reputation_system.get_reputation(leader_id)
            leader_reward *= (1 + self.REPUTATION_BONUS_RATE * rep)

        # 长期参与加成
        leader_reward *= self._compute_longevity_bonus(leader_id)

        rewards[leader_id] = leader_reward
        self._credit(leader_id, leader_reward, task_id, "consensus_proposal",
                     f"Leader 成功提案")

        # === Backup 奖励 ===
        for voter_id in voter_ids:
            if voter_id == leader_id:
                continue

            voter_reward = self.BASE_VALIDATION_REWARD

            # 信誉加成
            if self.reputation_system:
                rep = self.reputation_system.get_reputation(voter_id)
                voter_reward *= (1 + self.REPUTATION_BONUS_RATE * rep)

            # 长期参与加成
            voter_reward *= self._compute_longevity_bonus(voter_id)

            rewards[voter_id] = voter_reward
            self._credit(voter_id, voter_reward, task_id, "consensus_validation",
                         f"Backup 正确验证")

        # 从激励池中扣除
        total_reward = sum(rewards.values())
        self.incentive_pool -= total_reward

        print(f"[激励] 任务 {task_id} 奖励分配: 总额={total_reward:.2f}, "
              f"Leader={leader_id}({rewards.get(leader_id, 0):.2f}), "
              f"激励池余额={self.incentive_pool:.2f}")

        return rewards

    def apply_penalty(
        self,
        agent_id: str,
        penalty_type: PenaltyType,
        task_id: str = "",
        reason: str = "",
        custom_amount: float = None,
    ) -> float:
        """
        对 Agent 应用惩罚

        惩罚优先从账户余额扣除，不足部分从 DID 质押中罚没

        Args:
            agent_id: Agent ID
            penalty_type: 惩罚类型
            task_id: 任务 ID
            reason: 惩罚原因
            custom_amount: 自定义金额（覆盖默认值）

        Returns:
            实际罚没金额
        """
        # 确定罚金
        penalty_amounts = {
            PenaltyType.MALICIOUS_PROPOSAL: self.MALICIOUS_PROPOSAL_PENALTY,
            PenaltyType.MALICIOUS_VOTE: self.MALICIOUS_VOTE_PENALTY,
            PenaltyType.TIMEOUT: self.TIMEOUT_PENALTY,
            PenaltyType.OFFLINE: self.OFFLINE_PENALTY,
            PenaltyType.LOW_REPUTATION: 20.0,
            PenaltyType.SYBIL_ATTACK: 100.0,
        }

        amount = custom_amount if custom_amount is not None else penalty_amounts.get(penalty_type, 10.0)

        # 从账户余额扣除
        balance = self._balances.get(agent_id, 0.0)
        if balance >= amount:
            self._balances[agent_id] = balance - amount
        else:
            # 余额不足，从质押罚没
            remaining = amount - balance
            self._balances[agent_id] = 0.0

            if self.did_registry:
                did = self.did_registry.get_did(agent_id)
                if did:
                    # 按比例罚没质押
                    slash_ratio = min(1.0, remaining / self.did_registry.resolve(did).stake_amount) if self.did_registry.resolve(did).stake_amount > 0 else 0
                    if slash_ratio > 0:
                        success, slashed = self.did_registry.slash_stake(did, ratio=slash_ratio)
                        remaining = slashed  # 实际罚没金额

        # 罚没金额注入激励池
        self.incentive_pool += amount

        # 记录
        self._debit(agent_id, amount, task_id, penalty_type.value, reason)

        self.stats["total_penalties_collected"] += amount
        self.stats["total_penalty_count"] += 1

        print(f"[激励] 惩罚 {agent_id}: 类型={penalty_type.value}, 金额={amount:.2f}, 原因={reason}")

        return amount

    # ========== 查询与统计 ==========

    def get_balance(self, agent_id: str) -> float:
        """获取 Agent 账户余额"""
        return self._balances.get(agent_id, 0.0)

    def get_all_balances(self) -> Dict[str, float]:
        """获取所有 Agent 的余额"""
        return dict(self._balances)

    def get_contribution_score(self, agent_id: str) -> float:
        """
        计算综合贡献度评分

        贡献度 = (奖励累积 + 信誉加权 + 参与度加权) / 3

        Args:
            agent_id: Agent ID

        Returns:
            贡献度分数 (0.0-1.0)
        """
        # 奖励累积归一化
        total_rewards = sum(
            r.amount for r in self._records
            if r.agent_id == agent_id and r.record_type == "reward"
        )
        reward_score = min(1.0, total_rewards / 100.0)  # 100 为满分线

        # 信誉加权
        rep_score = 0.5
        if self.reputation_system:
            rep_score = self.reputation_system.get_reputation(agent_id)

        # 参与度（投票次数归一化）
        vote_count = sum(
            1 for r in self._records
            if r.agent_id == agent_id and "validation" in r.reason
        )
        participation_score = min(1.0, vote_count / 20.0)  # 20次为满分

        return (reward_score + rep_score + participation_score) / 3

    def get_leaderboard(self, limit: int = 10) -> List[Dict]:
        """
        获取贡献度排行榜

        Args:
            limit: 返回条数

        Returns:
            排行榜列表
        """
        all_agents = set(self._balances.keys())
        if self.reputation_system:
            all_agents.update(self.reputation_system.get_all_reputations().keys())

        leaderboard = []
        for agent_id in all_agents:
            leaderboard.append({
                "agent_id": agent_id,
                "balance": self.get_balance(agent_id),
                "contribution_score": self.get_contribution_score(agent_id),
                "reputation": self.reputation_system.get_reputation(agent_id) if self.reputation_system else 0,
            })

        # 按贡献度排序
        leaderboard.sort(key=lambda x: x["contribution_score"], reverse=True)
        return leaderboard[:limit]

    def get_stats(self) -> Dict:
        """获取激励系统统计"""
        return {
            **self.stats,
            "incentive_pool_balance": self.incentive_pool,
            "initial_pool": self.initial_pool,
            "total_accounts": len(self._balances),
            "pool_utilization": (self.initial_pool - self.incentive_pool) / self.initial_pool if self.initial_pool > 0 else 0,
        }

    def get_agent_incentive_report(self, agent_id: str) -> Dict:
        """获取 Agent 的激励报告"""
        agent_records = [r for r in self._records if r.agent_id == agent_id]
        total_rewards = sum(r.amount for r in agent_records if r.record_type == "reward")
        total_penalties = sum(r.amount for r in agent_records if r.record_type == "penalty")

        return {
            "agent_id": agent_id,
            "balance": self.get_balance(agent_id),
            "total_rewards": total_rewards,
            "total_penalties": total_penalties,
            "net_income": total_rewards - total_penalties,
            "contribution_score": self.get_contribution_score(agent_id),
            "recent_records": [
                {
                    "type": r.record_type,
                    "amount": r.amount,
                    "reason": r.reason,
                    "task_id": r.task_id,
                }
                for r in agent_records[-5:]
            ],
        }

    # ========== 内部方法 ==========

    def _credit(self, agent_id: str, amount: float, task_id: str, reward_type: str, reason: str):
        """记录奖励"""
        self._record_counter += 1
        did = self.did_registry.get_did(agent_id) if self.did_registry else ""

        record = IncentiveRecord(
            record_id=f"inc_{self._record_counter:06d}",
            agent_id=agent_id,
            did=did or "",
            record_type="reward",
            amount=amount,
            reason=reason,
            task_id=task_id,
            details={"reward_type": reward_type},
        )
        self._records.append(record)

        # 更新余额
        self._balances[agent_id] = self._balances.get(agent_id, 0.0) + amount

        self.stats["total_rewards_distributed"] += amount
        self.stats["total_reward_count"] += 1

    def _debit(self, agent_id: str, amount: float, task_id: str, penalty_type: str, reason: str):
        """记录惩罚"""
        self._record_counter += 1
        did = self.did_registry.get_did(agent_id) if self.did_registry else ""

        record = IncentiveRecord(
            record_id=f"inc_{self._record_counter:06d}",
            agent_id=agent_id,
            did=did or "",
            record_type="penalty",
            amount=amount,
            reason=reason or penalty_type,
            task_id=task_id,
            details={"penalty_type": penalty_type},
        )
        self._records.append(record)

    def _compute_longevity_bonus(self, agent_id: str) -> float:
        """计算长期参与加成"""
        task_count = sum(
            1 for r in self._records
            if r.agent_id == agent_id and r.record_type == "reward"
        )
        if task_count >= self.LONGEVITY_BONUS_THRESHOLD:
            return 1.0 + self.LONGEVITY_BONUS_RATE * (task_count / self.LONGEVITY_BONUS_THRESHOLD)
        return 1.0


# ========== 快速测试 ==========

if __name__ == "__main__":
    print("=" * 60)
    print("  激励系统测试")
    print("=" * 60)

    from did_registry import DIDRegistry
    from reputation import ReputationSystem

    # 创建依赖系统
    registry = DIDRegistry(min_stake=100.0)
    rep_system = ReputationSystem(did_registry=registry)

    # 注册 Agent
    for i in range(1, 6):
        registry.register(f"agent_{i}", stake_amount=200.0, specialty="math")
        rep_system._reputations[f"agent_{i}"] = 1.0

    # 创建激励系统
    incentive = IncentiveSystem(
        did_registry=registry,
        reputation_system=rep_system,
        initial_pool=10000.0,
    )

    # 测试1: 分配奖励
    print("\n--- 测试1: 奖励分配 ---")
    rewards = incentive.distribute_consensus_rewards(
        task_id="task_001",
        leader_id="agent_1",
        voter_ids=["agent_2", "agent_3", "agent_4", "agent_5"],
        success=True,
        leader_answer="1081",
        correct_answer="1081",
    )
    print(f"奖励分配: {rewards}")

    # 测试2: 惩罚
    print("\n--- 测试2: 惩罚 ---")
    penalty = incentive.apply_penalty(
        agent_id="agent_4",
        penalty_type=PenaltyType.MALICIOUS_VOTE,
        task_id="task_001",
        reason="持续投反对票",
    )
    print(f"惩罚金额: {penalty:.2f}")

    # 测试3: 查看余额
    print("\n--- 测试3: 余额 ---")
    for aid in ["agent_1", "agent_2", "agent_4"]:
        print(f"  {aid}: balance={incentive.get_balance(aid):.2f}, "
              f"contribution={incentive.get_contribution_score(aid):.3f}")

    # 测试4: 排行榜
    print("\n--- 测试4: 排行榜 ---")
    lb = incentive.get_leaderboard()
    for entry in lb:
        print(f"  {entry['agent_id']}: score={entry['contribution_score']:.3f}, "
              f"balance={entry['balance']:.2f}")

    # 测试5: 统计
    print("\n--- 测试5: 统计 ---")
    stats = incentive.get_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")
