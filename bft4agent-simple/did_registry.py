"""
分布式数字身份（DID）注册与管理系统

为每个 Agent 提供唯一的链上身份标识，实现：
1. DID 生成与注册（模拟链上注册）
2. 可验证凭证（VC）管理
3. 身份验证与防女巫攻击（质押机制）
4. DID 文档管理

W3C DID 规范简化实现：
- DID 格式: did:bft4agent:<agent_id>
- DID 文档包含：公钥、服务端点、可验证凭证
"""

import time
import json
import hashlib
import secrets
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class DIDStatus(Enum):
    """DID 身份状态"""
    ACTIVE = "active"         # 正常活跃
    SUSPENDED = "suspended"   # 已暂停（信誉过低）
    REVOKED = "revoked"       # 已吊销（严重违规）


class CredentialType(Enum):
    """可验证凭证类型"""
    IDENTITY = "identity"             # 基础身份凭证
    SPECIALTY = "specialty"           # 专业领域凭证
    REPUTATION = "reputation"         # 信誉凭证
    STAKE = "stake"                   # 质押凭证


@dataclass
class VerifiableCredential:
    """可验证凭证 (Verifiable Credential)"""
    credential_id: str
    credential_type: CredentialType
    issuer: str                # 颁发者 DID
    subject: str               # 持有者 DID
    claims: Dict               # 凭证声明内容
    issued_at: float
    expires_at: float
    proof: str = ""            # 签名证明（简化模拟）

    def is_expired(self) -> bool:
        """检查凭证是否过期"""
        return time.time() > self.expires_at

    def to_dict(self) -> Dict:
        return {
            "credential_id": self.credential_id,
            "type": self.credential_type.value,
            "issuer": self.issuer,
            "subject": self.subject,
            "claims": self.claims,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "proof": self.proof,
        }


@dataclass
class DIDDocument:
    """
    DID 文档 (W3C DID Document 简化版)

    每个 Agent 在链上注册后生成对应的 DID 文档
    """
    did: str                             # DID 标识符
    controller: str                      # 控制者
    public_key: str                      # 公钥（模拟）
    created_at: float                    # 创建时间
    updated_at: float                    # 更新时间
    status: DIDStatus = DIDStatus.ACTIVE # 当前状态
    stake_amount: float = 0.0            # 质押金额
    credentials: List[VerifiableCredential] = field(default_factory=list)
    service_endpoint: str = ""           # 服务端点
    metadata: Dict = field(default_factory=dict)  # 扩展元数据

    def add_credential(self, vc: VerifiableCredential):
        """添加可验证凭证"""
        self.credentials.append(vc)
        self.updated_at = time.time()

    def get_credential(self, cred_type: CredentialType) -> Optional[VerifiableCredential]:
        """获取指定类型的有效凭证"""
        for vc in self.credentials:
            if vc.credential_type == cred_type and not vc.is_expired():
                return vc
        return None

    def to_dict(self) -> Dict:
        return {
            "did": self.did,
            "controller": self.controller,
            "public_key": self.public_key,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status.value,
            "stake_amount": self.stake_amount,
            "credentials": [vc.to_dict() for vc in self.credentials],
            "service_endpoint": self.service_endpoint,
            "metadata": self.metadata,
        }


class DIDRegistry:
    """
    DID 注册表（模拟链上注册表）

    提供去中心化的身份注册、验证和管理功能。
    在生产环境中，这些操作将部署在真实的区块链上。

    核心功能：
    1. DID 创建与注册（需要质押）
    2. 身份验证与查询
    3. 凭证颁发与管理
    4. 女巫攻击防护（基于质押和唯一性约束）
    5. 身份状态管理（活跃/暂停/吊销）
    """

    # ========== 系统级常量 ==========
    MIN_STAKE_AMOUNT = 100.0       # 最低质押金额
    STAKE_SLASH_RATIO = 0.5        # 惩罚时扣除质押比例
    CREDENTIAL_VALIDITY = 86400 * 30  # 凭证有效期（30天，秒）

    def __init__(self, min_stake: float = None):
        """
        初始化 DID 注册表

        Args:
            min_stake: 最低质押金额（默认使用系统常量）
        """
        # 注册表存储 {did: DIDDocument}
        self._registry: Dict[str, DIDDocument] = {}
        # agent_id 到 DID 的映射（防止一个 agent 注册多个 DID）
        self._id_to_did: Dict[str, str] = {}
        # 公钥到 DID 的映射（防止公钥重复使用）
        self._pubkey_to_did: Dict[str, str] = {}

        if min_stake is not None:
            self.MIN_STAKE_AMOUNT = min_stake

        # 统计信息
        self.stats = {
            "total_registered": 0,
            "total_revoked": 0,
            "total_suspended": 0,
            "total_stake_slashed": 0.0,
        }

    # ========== DID 生命周期管理 ==========

    def register(
        self,
        agent_id: str,
        stake_amount: float = None,
        specialty: str = "general",
        metadata: Dict = None,
    ) -> Tuple[str, DIDDocument]:
        """
        注册一个新的 DID 身份

        流程：
        1. 检查 agent_id 是否已注册（防女巫）
        2. 生成密钥对和 DID
        3. 验证质押金额
        4. 创建 DID 文档
        5. 颁发初始凭证

        Args:
            agent_id: Agent 唯一标识
            stake_amount: 质押金额
            specialty: 专业领域
            metadata: 扩展元数据

        Returns:
            (did, did_document) 元组

        Raises:
            ValueError: 注册失败（已注册、质押不足等）
        """
        # === 1. 女巫攻击防护 ===
        if agent_id in self._id_to_did:
            raise ValueError(
                f"Agent '{agent_id}' 已注册 DID: {self._id_to_did[agent_id]}。"
                f"一个 Agent 只能注册一个 DID（防止女巫攻击）。"
            )

        # === 2. 质押验证 ===
        stake = stake_amount if stake_amount is not None else self.MIN_STAKE_AMOUNT
        if stake < self.MIN_STAKE_AMOUNT:
            raise ValueError(
                f"质押金额 {stake} 低于最低要求 {self.MIN_STAKE_AMOUNT}。"
                f"请增加质押以注册 DID。"
            )

        # === 3. 生成密钥对和 DID ===
        private_key, public_key = self._generate_key_pair(agent_id)
        did = f"did:bft4agent:{agent_id}"

        # 检查公钥唯一性
        if public_key in self._pubkey_to_did:
            raise ValueError(f"公钥已被使用，存在身份冒用风险。")

        # === 4. 创建 DID 文档 ===
        now = time.time()
        did_doc = DIDDocument(
            did=did,
            controller=did,
            public_key=public_key,
            created_at=now,
            updated_at=now,
            status=DIDStatus.ACTIVE,
            stake_amount=stake,
            service_endpoint=f"p2p://{agent_id}",
            metadata=metadata or {},
        )

        # === 5. 颁发初始凭证 ===
        # 身份凭证
        identity_vc = self._issue_credential(
            issuer="did:bft4agent:system",
            subject=did,
            cred_type=CredentialType.IDENTITY,
            claims={
                "agent_id": agent_id,
                "registered_at": now,
                "stake_amount": stake,
            }
        )
        did_doc.add_credential(identity_vc)

        # 专业领域凭证
        specialty_vc = self._issue_credential(
            issuer="did:bft4agent:system",
            subject=did,
            cred_type=CredentialType.SPECIALTY,
            claims={
                "specialty": specialty,
                "verified": True,
            }
        )
        did_doc.add_credential(specialty_vc)

        # 质押凭证
        stake_vc = self._issue_credential(
            issuer="did:bft4agent:system",
            subject=did,
            cred_type=CredentialType.STAKE,
            claims={
                "amount": stake,
                "currency": "token",
                "locked": True,
            }
        )
        did_doc.add_credential(stake_vc)

        # === 6. 写入注册表 ===
        self._registry[did] = did_doc
        self._id_to_did[agent_id] = did
        self._pubkey_to_did[public_key] = did

        self.stats["total_registered"] += 1

        print(f"[DID] 注册成功: {did}")
        print(f"  质押金额: {stake}")
        print(f"  公钥: {public_key[:16]}...")
        print(f"  凭证数: {len(did_doc.credentials)}")

        return did, did_doc

    def resolve(self, did: str) -> Optional[DIDDocument]:
        """
        解析 DID，获取 DID 文档

        Args:
            did: DID 标识符

        Returns:
            DID 文档，不存在则返回 None
        """
        return self._registry.get(did)

    def resolve_by_agent_id(self, agent_id: str) -> Optional[DIDDocument]:
        """
        通过 agent_id 查找 DID 文档

        Args:
            agent_id: Agent 唯一标识

        Returns:
            DID 文档，不存在则返回 None
        """
        did = self._id_to_did.get(agent_id)
        if did:
            return self._registry.get(did)
        return None

    def verify_identity(self, did: str) -> Tuple[bool, str]:
        """
        验证 DID 身份是否有效

        检查项：
        1. DID 是否已注册
        2. 身份状态是否为 ACTIVE
        3. 身份凭证是否有效

        Args:
            did: DID 标识符

        Returns:
            (is_valid, reason) 元组
        """
        doc = self._registry.get(did)
        if not doc:
            return False, f"DID '{did}' 未注册"

        if doc.status == DIDStatus.REVOKED:
            return False, f"DID '{did}' 已被吊销"

        if doc.status == DIDStatus.SUSPENDED:
            return False, f"DID '{did}' 已被暂停"

        # 检查身份凭证
        identity_vc = doc.get_credential(CredentialType.IDENTITY)
        if not identity_vc:
            return False, f"DID '{did}' 缺少有效的身份凭证"

        if identity_vc.is_expired():
            return False, f"DID '{did}' 身份凭证已过期"

        return True, "身份验证通过"

    def is_registered(self, agent_id: str) -> bool:
        """检查 agent 是否已注册 DID"""
        return agent_id in self._id_to_did

    def get_did(self, agent_id: str) -> Optional[str]:
        """获取 agent 的 DID"""
        return self._id_to_did.get(agent_id)

    # ========== 身份状态管理 ==========

    def suspend(self, did: str, reason: str = "") -> bool:
        """
        暂停 DID 身份（信誉过低时触发）

        Args:
            did: DID 标识符
            reason: 暂停原因

        Returns:
            是否成功
        """
        doc = self._registry.get(did)
        if not doc:
            return False

        if doc.status != DIDStatus.ACTIVE:
            return False

        doc.status = DIDStatus.SUSPENDED
        doc.updated_at = time.time()
        doc.metadata["suspend_reason"] = reason
        doc.metadata["suspended_at"] = time.time()

        self.stats["total_suspended"] += 1
        print(f"[DID] 暂停: {did}, 原因: {reason}")
        return True

    def reactivate(self, did: str) -> bool:
        """
        重新激活已暂停的 DID

        Args:
            did: DID 标识符

        Returns:
            是否成功
        """
        doc = self._registry.get(did)
        if not doc or doc.status != DIDStatus.SUSPENDED:
            return False

        doc.status = DIDStatus.ACTIVE
        doc.updated_at = time.time()
        doc.metadata["reactivated_at"] = time.time()

        print(f"[DID] 重新激活: {did}")
        return True

    def revoke(self, did: str, reason: str = "") -> Tuple[bool, float]:
        """
        吊销 DID 身份并罚没全部质押（严重违规时触发）

        Args:
            did: DID 标识符
            reason: 吊销原因

        Returns:
            (是否成功, 罚没金额) 元组
        """
        doc = self._registry.get(did)
        if not doc:
            return False, 0.0

        if doc.status == DIDStatus.REVOKED:
            return False, 0.0

        slashed_amount = doc.stake_amount
        doc.status = DIDStatus.REVOKED
        doc.updated_at = time.time()
        doc.metadata["revoke_reason"] = reason
        doc.metadata["revoked_at"] = time.time()
        doc.stake_amount = 0.0

        self.stats["total_revoked"] += 1
        self.stats["total_stake_slashed"] += slashed_amount

        print(f"[DID] 吊销: {did}, 原因: {reason}, 罚没: {slashed_amount}")
        return True, slashed_amount

    def slash_stake(self, did: str, ratio: float = None) -> Tuple[bool, float]:
        """
        部分罚没质押（恶意行为惩罚）

        Args:
            did: DID 标识符
            ratio: 罚没比例（0.0-1.0）

        Returns:
            (是否成功, 罚没金额) 元组
        """
        doc = self._registry.get(did)
        if not doc:
            return False, 0.0

        slash_ratio = ratio if ratio is not None else self.STAKE_SLASH_RATIO
        slash_amount = doc.stake_amount * slash_ratio
        doc.stake_amount -= slash_amount
        doc.updated_at = time.time()

        self.stats["total_stake_slashed"] += slash_amount

        # 质押低于最低要求时暂停身份
        if doc.stake_amount < self.MIN_STAKE_AMOUNT:
            self.suspend(did, f"质押低于最低要求 ({doc.stake_amount:.2f} < {self.MIN_STAKE_AMOUNT})")

        print(f"[DID] 罚没质押: {did}, 比例: {slash_ratio:.0%}, 金额: {slash_amount:.2f}, 剩余: {doc.stake_amount:.2f}")
        return True, slash_amount

    def add_stake(self, did: str, amount: float) -> bool:
        """
        追加质押

        Args:
            did: DID 标识符
            amount: 追加金额

        Returns:
            是否成功
        """
        doc = self._registry.get(did)
        if not doc:
            return False

        doc.stake_amount += amount
        doc.updated_at = time.time()

        # 如果追加质押后满足要求，自动恢复活跃状态
        if doc.status == DIDStatus.SUSPENDED and doc.stake_amount >= self.MIN_STAKE_AMOUNT:
            self.reactivate(did)

        print(f"[DID] 追加质押: {did}, 金额: {amount:.2f}, 总质押: {doc.stake_amount:.2f}")
        return True

    # ========== 凭证管理 ==========

    def issue_reputation_credential(
        self,
        did: str,
        reputation_score: float,
        total_tasks: int,
        success_rate: float,
    ) -> Optional[VerifiableCredential]:
        """
        颁发信誉凭证

        Args:
            did: 目标 DID
            reputation_score: 信誉分数
            total_tasks: 参与任务总数
            success_rate: 成功率

        Returns:
            颁发的凭证，失败返回 None
        """
        doc = self._registry.get(did)
        if not doc:
            return None

        # 移除旧的信誉凭证
        doc.credentials = [
            vc for vc in doc.credentials
            if vc.credential_type != CredentialType.REPUTATION
        ]

        # 颁发新凭证
        vc = self._issue_credential(
            issuer="did:bft4agent:system",
            subject=did,
            cred_type=CredentialType.REPUTATION,
            claims={
                "reputation_score": reputation_score,
                "total_tasks": total_tasks,
                "success_rate": success_rate,
                "level": self._compute_reputation_level(reputation_score),
            }
        )
        doc.add_credential(vc)

        return vc

    def get_reputation_credential(self, did: str) -> Optional[Dict]:
        """获取信誉凭证信息"""
        doc = self._registry.get(did)
        if not doc:
            return None

        vc = doc.get_credential(CredentialType.REPUTATION)
        return vc.to_dict() if vc else None

    # ========== 查询与统计 ==========

    def get_all_active_dids(self) -> List[str]:
        """获取所有活跃的 DID 列表"""
        return [
            did for did, doc in self._registry.items()
            if doc.status == DIDStatus.ACTIVE
        ]

    def get_stake_info(self, did: str) -> Optional[Dict]:
        """获取质押信息"""
        doc = self._registry.get(did)
        if not doc:
            return None

        stake_vc = doc.get_credential(CredentialType.STAKE)
        return {
            "did": did,
            "current_stake": doc.stake_amount,
            "initial_stake": stake_vc.claims.get("amount", 0) if stake_vc else 0,
            "status": doc.status.value,
        }

    def get_stats(self) -> Dict:
        """获取注册表统计信息"""
        active_count = sum(1 for doc in self._registry.values() if doc.status == DIDStatus.ACTIVE)
        suspended_count = sum(1 for doc in self._registry.values() if doc.status == DIDStatus.SUSPENDED)
        total_stake = sum(doc.stake_amount for doc in self._registry.values())

        return {
            **self.stats,
            "active_dids": active_count,
            "suspended_dids": suspended_count,
            "total_stake_locked": total_stake,
            "registry_size": len(self._registry),
        }

    def get_registry_snapshot(self) -> List[Dict]:
        """获取注册表快照（用于实验记录）"""
        return [doc.to_dict() for doc in self._registry.values()]

    # ========== 内部方法 ==========

    def _generate_key_pair(self, agent_id: str) -> Tuple[str, str]:
        """
        生成密钥对（模拟）

        在生产环境中应使用真实的非对称加密算法（如 Ed25519, secp256k1）

        Returns:
            (private_key, public_key) 元组
        """
        seed = f"{agent_id}:{secrets.token_hex(16)}:{time.time()}"
        private_key = hashlib.sha256(seed.encode()).hexdigest()
        public_key = hashlib.sha256(private_key.encode()).hexdigest()

        return private_key, public_key

    def _issue_credential(
        self,
        issuer: str,
        subject: str,
        cred_type: CredentialType,
        claims: Dict,
    ) -> VerifiableCredential:
        """
        颁发可验证凭证

        Args:
            issuer: 颁发者 DID
            subject: 持有者 DID
            cred_type: 凭证类型
            claims: 凭证声明

        Returns:
            可验证凭证
        """
        now = time.time()
        cred_id = f"vc:{cred_type.value}:{hashlib.sha256(f'{subject}:{now}'.encode()).hexdigest()[:12]}"

        # 生成签名证明（模拟）
        proof_data = f"{cred_id}:{issuer}:{subject}:{json.dumps(claims, sort_keys=True)}"
        proof = f"proof_{hashlib.sha256(proof_data.encode()).hexdigest()[:16]}"

        return VerifiableCredential(
            credential_id=cred_id,
            credential_type=cred_type,
            issuer=issuer,
            subject=subject,
            claims=claims,
            issued_at=now,
            expires_at=now + self.CREDENTIAL_VALIDITY,
            proof=proof,
        )

    def _compute_reputation_level(self, score: float) -> str:
        """根据信誉分数计算等级"""
        if score >= 0.9:
            return "excellent"
        elif score >= 0.7:
            return "good"
        elif score >= 0.5:
            return "average"
        elif score >= 0.3:
            return "poor"
        else:
            return "dangerous"


# ========== 快速测试 ==========

if __name__ == "__main__":
    print("=" * 60)
    print("  DID 注册表测试")
    print("=" * 60)

    registry = DIDRegistry(min_stake=100.0)

    # 测试1: 正常注册
    print("\n--- 测试1: 正常注册 ---")
    did1, doc1 = registry.register("agent_1", stake_amount=200.0, specialty="math")
    did2, doc2 = registry.register("agent_2", stake_amount=150.0, specialty="logic")
    did3, doc3 = registry.register("agent_3", stake_amount=100.0, specialty="verification")

    # 测试2: 女巫攻击防护
    print("\n--- 测试2: 女巫攻击防护 ---")
    try:
        registry.register("agent_1", stake_amount=500.0)  # 重复注册
    except ValueError as e:
        print(f"[OK] 防护成功: {e}")

    # 测试3: 身份验证
    print("\n--- 测试3: 身份验证 ---")
    valid, reason = registry.verify_identity(did1)
    print(f"DID1 验证: valid={valid}, reason={reason}")

    # 测试4: 部分罚没
    print("\n--- 测试4: 部分罚没 ---")
    success, amount = registry.slash_stake(did2, ratio=0.3)
    print(f"罚没: success={success}, amount={amount:.2f}")

    # 测试5: 信誉凭证
    print("\n--- 测试5: 信誉凭证 ---")
    vc = registry.issue_reputation_credential(did1, 0.85, 10, 0.9)
    print(f"信誉凭证: {vc.to_dict() if vc else 'None'}")

    # 测试6: 完全吊销
    print("\n--- 测试6: 完全吊销 ---")
    success, slashed = registry.revoke(did3, reason="严重违规")
    print(f"吊销: success={success}, 罚没={slashed:.2f}")

    # 测试7: 统计信息
    print("\n--- 测试7: 统计信息 ---")
    stats = registry.get_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")

    # 测试8: 注册表快照
    print("\n--- 测试8: 注册表快照 ---")
    snapshot = registry.get_registry_snapshot()
    for doc in snapshot:
        print(f"  {doc['did']}: status={doc['status']}, stake={doc['stake_amount']:.2f}")