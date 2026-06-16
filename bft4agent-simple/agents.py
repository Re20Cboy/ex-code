"""
Agentnode实现

简化的Agent实现，支持Leader和Backup角色
集成 DID 身份系统和行为追踪日志
"""

import time
import random
from typing import Dict, List, Optional, Callable

# DID 和行为日志模块
from did_registry import DIDRegistry, DIDStatus
from behavior_log import BehaviorLog, BehaviorEventType


class Agent:
    """单个Agentnode（集成了DID身份）"""

    def __init__(
        self,
        agent_id: str,
        role: str = "backup",  # leader | backup（BFT角色）
        reputation: float = 1.0,
        is_malicious: bool = False,
        llm_caller: Optional[Callable] = None,
        role_config: Optional[Dict] = None,  # 专业领域角色配置
        malicious_peers: Optional[List[str]] = None,  # 恶意同伙列表
        malicious_answers_config: Optional[Dict] = None,  # 恶意节点的硬编码错误答案
        did_registry: Optional[DIDRegistry] = None,  # DID注册表
        behavior_log: Optional[BehaviorLog] = None,  # 行为日志
    ):
        """
        initAgent

        Args:
            agent_id: Agent唯一ID
            role: 角色（leader或backup，BFT协议角色）
            reputation: 信誉分数 (0.0-1.0)
            is_malicious: 是否为maliciousnode
            llm_caller: LLM调用函数
            role_config: 专业领域角色配置（如：数学专家、逻辑分析师等）
            malicious_peers: 恶意同伙的ID列表（用于协同攻击）
            malicious_answers_config: 恶意节点的硬编码错误答案配置
            did_registry: DID注册表实例（用于身份管理）
            behavior_log: 行为日志实例（用于行为追踪）
        """
        self.id = agent_id
        self.role = role  # BFT协议角色：leader/backup
        self.reputation = reputation
        self.is_malicious = is_malicious
        self.llm_caller = llm_caller

        # 恶意答案配置（用于恶意节点生成固定的错误答案）
        self.malicious_answers_config = malicious_answers_config or {}

        # 专业领域角色配置
        self.role_config = role_config or {}
        self.specialty = self.role_config.get("specialty", "general")
        self.system_prompt = self.role_config.get("system_prompt", "")
        self.validation_style = self.role_config.get("validation_style", "balanced")

        # 恶意同伙列表（用于协同攻击）
        self.malicious_peers = malicious_peers or []

        # === DID 身份系统 ===
        self.did_registry = did_registry
        self.behavior_log = behavior_log
        self.did: Optional[str] = None  # 注册后填入

        # === 信誉与激励相关 ===
        self.voting_weight: float = 1.0  # 投票权重（由信誉系统计算）
        self.total_rewards: float = 0.0   # 累计奖励
        self.total_penalties: float = 0.0 # 累计惩罚
        self.tasks_participated: int = 0  # 参与任务数
        self.tasks_success: int = 0       # 成功任务数

        # 状态
        self.last_seen = time.time()
        self.message_queue = []

    def register_did(self, stake_amount: float = None) -> str:
        """
        注册 DID 身份

        Args:
            stake_amount: 质押金额

        Returns:
            DID 标识符

        Raises:
            ValueError: 注册失败
        """
        if not self.did_registry:
            raise ValueError("DID注册表未初始化")

        did, doc = self.did_registry.register(
            agent_id=self.id,
            stake_amount=stake_amount,
            specialty=self.specialty,
            metadata={
                "role_config": self.role_config.get("name", ""),
                "is_malicious": self.is_malicious,  # 仅实验用，真实系统中不可见
            },
        )
        self.did = did
        return did

    def is_did_active(self) -> bool:
        """检查 DID 身份是否有效且活跃"""
        if not self.did or not self.did_registry:
            return False
        valid, _ = self.did_registry.verify_identity(self.did)
        return valid

    def propose(self, task: Dict) -> Dict:
        """
        Leader: 生成reasoningproposal

        Args:
            task: task字典 {"content": "2+2=?", "type": "math"}

        Returns:
            proposal字典 {
                "task_id": "...",
                "leader_id": "...",
                "reasoning": ["步骤1", "步骤2"],
                "answer": "4",
                "confidence": 0.95
            }
        """
        if self.role != "leader":
            raise ValueError(f"Agent {self.id} is not a leader")

        # === 恶意leader策略：故意生成错误答案 ===
        print(f"[PROPOSE DEBUG] Agent {self.id}, is_malicious={self.is_malicious}, role={self.role}")
        if self.is_malicious:
            print(f"[PROPOSE DEBUG] 调用恶意提案逻辑 _malicious_propose")
            return self._malicious_propose(task)
        else:
            print(f"[PROPOSE DEBUG] 调用诚实提案逻辑（使用LLM）")

        # 诚实leader的正常逻辑
        # 构建带有角色信息的prompt
        prompt = self._build_generation_prompt(task["content"])

        # 调用LLM生成reasoning
        if self.llm_caller:
            reasoning, answer = self.llm_caller.generate(prompt)
        else:
            # 简单模拟
            reasoning = ["分析问题", "计算result"]
            answer = self._mock_answer(task["content"])

        proposal = {
            "task_id": task.get("task_id", f"task_{int(time.time())}"),
            "task_content": task.get("content", ""),  # 添加原始问题内容
            "leader_id": self.id,
            "reasoning": reasoning,
            "answer": answer,
            "confidence": 0.95,
            "timestamp": time.time(),
            "leader_specialty": self.specialty,  # 添加leader的专业领域
        }

        return proposal

    def validate(self, proposal: Dict) -> Dict:
        """
        Backup: validateproposal

        Args:
            proposal: proposal字典

        Returns:
            vote字典 {
                "voter_id": "...",
                "proposal_hash": "...",
                "decision": "Y",  # Y or N
                "confidence": 0.9,
                "reason": "..."
            }
        """
        # === 恶意backup策略：根据leader身份智能投票 ===
        if self.is_malicious:
            return self._malicious_vote_with_strategy(proposal)

        # 诚实backup的正常逻辑
        # 构建带有角色信息的验证prompt
        enhanced_proposal = self._build_validation_prompt(proposal)

        # 正常validate逻辑
        if self.llm_caller:
            decision = self.llm_caller.validate(enhanced_proposal)
        else:
            # 简单validate：检查proposal是否合理
            decision = "Y" if self._is_valid_proposal(proposal) else "N"

        vote = {
            "voter_id": self.id,
            "proposal_hash": self._hash_proposal(proposal),
            "decision": decision,
            "timestamp": time.time(),
            "voter_specialty": self.specialty,  # 添加验证者的专业领域
        }

        return vote

    def receive_message(self, message: Dict):
        """接收消息"""
        self.message_queue.append(message)
        self.last_seen = time.time()

    def heartbeat(self):
        """更新心跳"""
        self.last_seen = time.time()

    def update_reputation(self, delta: float):
        """更新信誉"""
        self.reputation = max(0.0, min(1.0, self.reputation + delta))

    # === 辅助方法 ===

    def _build_generation_prompt(self, question: str) -> str:
        """
        构建带有角色信息的生成prompt

        Args:
            question: 原始问题

        Returns:
            增强后的prompt
        """
        if not self.system_prompt:
            return question

        # 如果是恶意agent，添加恶意指令
        if self.is_malicious:
            malicious_instruction = "\n注意：请在答案中故意加入一个微小的错误，或者给出一个看似合理但实际错误的答案。"
            return f"{self.system_prompt}{malicious_instruction}\n\n问题: {question}"

        # 正常agent使用其专业领域的system prompt
        return f"{self.system_prompt}\n\n问题: {question}"

    def _build_validation_prompt(self, proposal: Dict) -> Dict:
        """
        构建带有角色信息的验证prompt

        Args:
            proposal: 原始proposal

        Returns:
            增强后的proposal
        """
        # 在proposal中添加验证者的角色信息
        enhanced_proposal = proposal.copy()

        # 添加验证提示
        validation_instruction = f"\n\n请从{self.role_config.get('name', '专家')}的角度进行验证。"

        # 根据验证风格调整提示
        if self.validation_style == "strict":
            validation_instruction += "请严格检查答案的准确性，任何不确定或可疑的地方都应该否定。"
        elif self.validation_style == "lenient":
            validation_instruction += "请以宽松的标准验证，只要答案基本合理即可通过。"
        else:  # balanced
            validation_instruction += "请以平衡的标准验证，既不苛刻也不随意。"

        # 修改task_id字段，添加验证提示
        original_task = enhanced_proposal.get("task_id", "")
        enhanced_proposal["task_id"] = f"{original_task}{validation_instruction}"

        return enhanced_proposal

    def _malicious_propose(self, task: Dict) -> Dict:
        """
        恶意leader的提案生成策略

        策略：使用配置中硬编码的错误答案，100%确保答案错误
        跳过LLM调用，直接返回预设的错误答案
        """
        # ========== 详细调试输出 ==========
        print(f"\n{'='*80}")
        print(f"[恶意Leader调试] 任务内容分析")
        print(f"{'='*80}")
        print(f"Task的所有字段:")
        for key, value in task.items():
            print(f"  [{key}]: {value}")
        print(f"{'='*80}\n")
        # ========================================

        # 从task中提取问题ID - 修复：从'id'字段而不是'task_id'字段读取
        real_task_id = task.get("id", "")  # 实际的字段名是'id'
        task_id_for_proposal = task.get("task_id", real_task_id)  # 用于proposal的task_id
        task_content = task.get("content", "")

        print(f"[DEBUG] real_task_id (from 'id' field) = '{real_task_id}'")
        print(f"[DEBUG] task_id_for_proposal = '{task_id_for_proposal}'")
        print(f"[DEBUG] task_content前100字符 = '{task_content[:100]}'")

        # 直接使用real_task_id作为question_id
        question_id = real_task_id

        print(f"[DEBUG] 最终question_id = '{question_id}'")

        # 从配置中获取错误答案
        wrong_answer = None
        if question_id and question_id in self.malicious_answers_config:
            wrong_answer = self.malicious_answers_config[question_id]
            print(f"[恶意Leader {self.id}] 使用硬编码错误答案 [{question_id}]: {wrong_answer}")
        elif "default_wrong_answer" in self.malicious_answers_config:
            wrong_answer = self.malicious_answers_config["default_wrong_answer"]
            print(f"[恶意Leader {self.id}] 使用默认错误答案: {wrong_answer}")
        else:
            # 如果配置中没有，使用一个通用的错误答案
            wrong_answer = "我不知道"
            print(f"[恶意Leader {self.id}] 使用备用错误答案: {wrong_answer}")

        # 生成假的推理链路（让恶意答案看起来更合理）
        reasoning = [
            f"分析问题: {task_content[:50]}...",
            "应用解题策略",
            f"得出答案: {wrong_answer}"
        ]

        proposal = {
            "task_id": task_id_for_proposal,
            "task_content": task_content,  # 添加原始问题内容
            "leader_id": self.id,
            "reasoning": reasoning,
            "answer": wrong_answer,
            "confidence": 0.95,  # 保持高置信度以迷惑其他节点
            "timestamp": time.time(),
            "leader_specialty": self.specialty,
        }

        print(f"[恶意Leader {self.id}] 生成了错误答案: {wrong_answer}")
        return proposal

    def _corrupt_answer(self, correct_answer: str) -> str:
        """
        将正确答案修改为错误答案

        策略：
        - 数学问题：总是修改结果，确保与正确答案不同
        - 对于小数字（如个位数），返回一个明显不同的数字
        - 对于大数字，返回错误的计算结果
        """
        try:
            # 尝试将答案转换为数字
            num = float(correct_answer)

            # 总是生成错误的答案（100%概率）
            # 确保生成的答案与正确答案明显不同
            if abs(num) < 10:
                # 小数字：返回一个明显不同的数字
                # 例如：4 → 99, 7 → 42, 等
                wrong_answers = [num + 10, num * 2, num + 5, 99, 42]
                return str(random.choice(wrong_answers))
            else:
                # 大数字：随机加减一个较大的数，或乘以一个系数
                operations = [
                    lambda x: x + random.randint(5, 20),
                    lambda x: x - random.randint(5, 20),
                    lambda x: x * random.choice([1.5, 2, 3]),
                    lambda x: int(x / 2),
                ]
                wrong_num = random.choice(operations)(num)
                return str(wrong_num)

        except:
            # 不是数字，返回固定错误答案
            return "Wrong Answer"

    def _malicious_vote_with_strategy(self, proposal: Dict) -> Dict:
        """
        恶意backup的智能投票策略

        策略：
        1. 如果leader也是恶意的（在malicious_peers列表中），投Y支持
        2. 如果leader不是恶意的，投N反对
        """
        leader_id = proposal.get("leader_id", "")

        # 检查leader是否是恶意同伙
        if leader_id in self.malicious_peers:
            # Leader是恶意同伙，投Y支持
            print(f"[恶意Backup {self.id}] Leader {leader_id}是同伙，投Y支持")
            decision = "Y"
            reason = f"支持同伙leader {leader_id}"
        else:
            # Leader不是恶意同伙，投N反对
            print(f"[恶意Backup {self.id}] Leader {leader_id}不是同伙，投N反对")
            decision = "N"
            reason = f"反对非同伙leader {leader_id}"

        return {
            "voter_id": self.id,
            "proposal_hash": self._hash_proposal(proposal),
            "decision": decision,
            "confidence": 0.95,
            "reason": reason,
            "timestamp": time.time(),
            "voter_specialty": self.specialty,
        }

    def _mock_answer(self, question: str) -> str:
        """简单的Mock回答"""
        try:
            # 尝试计算数学表达式
            if "=" in question:
                expr = question.split("=")[0].strip()
                result = eval(expr)
                return str(result)
        except:
            pass
        return "Mock Answer"

    def _is_valid_proposal(self, proposal: Dict) -> bool:
        """简单的proposalvalidate"""
        # 检查必要字段
        if "answer" not in proposal:
            return False

        if "reasoning" not in proposal or not proposal["reasoning"]:
            return False

        # 检查置信度
        if proposal.get("confidence", 0) < 0.5:
            return False

        return True

    def _hash_proposal(self, proposal: Dict) -> str:
        """计算proposal哈希"""
        import hashlib

        content = f"{proposal['leader_id']}:{proposal['answer']}:{proposal['timestamp']}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _malicious_vote(self, proposal: Dict) -> Dict:
        """maliciousnode的vote行为"""
        # 简单实现：随机vote
        decision = random.choice(["Y", "N"])

        return {
            "voter_id": self.id,
            "proposal_hash": self._hash_proposal(proposal),
            "decision": decision,
            "timestamp": time.time(),
        }

    def __repr__(self):
        did_str = f", did={self.did}" if self.did else ""
        return f"Agent({self.id}, role={self.role}, rep={self.reputation:.2f}, weight={self.voting_weight:.2f}{did_str})"


def create_agents(
    num_agents: int,
    malicious_ratio: float,
    llm_caller: Optional[Callable] = None,
    role_configs: Optional[List[Dict]] = None,
    random_assignment: bool = True,
    did_registry: Optional[DIDRegistry] = None,
    behavior_log: Optional[BehaviorLog] = None,
    stake_amount: float = None,
    malicious_answers_config: Optional[Dict] = None,
) -> List[Agent]:
    """
    创建Agent列表（集成DID注册）

    Args:
        num_agents: Agent总数
        malicious_ratio: maliciousnode比例
        llm_caller: LLM调用函数（所有agent共享同一个LLM）
        role_configs: 角色配置列表（可选）
        random_assignment: 是否随机分配角色（True=随机，False=按顺序）
        did_registry: DID注册表实例（可选）
        behavior_log: 行为日志实例（可选）
        stake_amount: 质押金额（可选，默认使用注册表最低要求）
        malicious_answers_config: 恶意节点答案配置

    Returns:
        Agent列表
    """
    agents = []

    num_malicious = int(num_agents * malicious_ratio)

    # 准备角色配置列表
    if role_configs is None:
        role_configs = []

    # 根据分配方式准备角色列表
    if random_assignment:
        # 随机分配：从角色配置中随机选择（允许重复）
        import random
        assigned_roles = [random.choice(role_configs) if role_configs else {}
                          for _ in range(num_agents)]
    else:
        # 按顺序分配：循环使用角色配置
        assigned_roles = []
        for i in range(num_agents):
            if role_configs:
                role_config = role_configs[i % len(role_configs)]
                assigned_roles.append(role_config)
            else:
                assigned_roles.append({})

    for i in range(num_agents):
        is_malicious = i < num_malicious
        agent_id = f"agent_{i+1}"

        agent = Agent(
            agent_id=agent_id,
            role="backup",  # 初始都是backup，后续选举leader
            reputation=1.0,
            is_malicious=is_malicious,
            llm_caller=llm_caller,
            role_config=assigned_roles[i],  # 分配角色配置
            malicious_peers=[],  # 先设置为空列表，稍后填充
            malicious_answers_config=malicious_answers_config if is_malicious else {},
            did_registry=did_registry,
            behavior_log=behavior_log,
        )

        # === DID 注册 ===
        if did_registry:
            try:
                agent.register_did(stake_amount=stake_amount)
            except ValueError as e:
                print(f"[WARNING] Agent {agent_id} DID注册失败: {e}")

        agents.append(agent)

    # === 为每个恶意agent设置malicious_peers列表 ===
    # 恶意agent之间可以相互识别，以便协同攻击
    malicious_agents = [agent.id for agent in agents if agent.is_malicious]

    for agent in agents:
        if agent.is_malicious:
            # 每个恶意agent都知道其他所有恶意agent的ID（不包括自己）
            agent.malicious_peers = [peer_id for peer_id in malicious_agents if peer_id != agent.id]
            print(f"[恶意节点配置] {agent.id} 的恶意同伙: {agent.malicious_peers}")

    return agents


if __name__ == "__main__":
    # testAgent创建
    print("=== Testing Agent Creation ===")

    agents = create_agents(num_agents=7, malicious_ratio=0.14)

    for agent in agents:
        print(agent)

    # testLeaderproposal
    print("\n=== Testing Leader Proposal ===")
    leader = Agent("agent_1", role="leader")
    task = {"content": "2+2=?", "type": "math"}
    proposal = leader.propose(task)
    print(f"Proposal: {proposal}")

    # testBackupvalidate
    print("\n=== Testing Backup Validation ===")
    backup = Agent("agent_2", role="backup")
    vote = backup.validate(proposal)
    print(f"Vote: {vote}")
