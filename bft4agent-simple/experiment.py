"""
BFT4Agent 信誉/激励系统长期有效性实验

4 组实验，验证 DID + 信誉 + 激励层在多维度上的效果：
  Exp1: 有激励 vs 无激励（长期运行对比）
  Exp2: 不同恶意节点比例下的鲁棒性
  Exp3: 信誉分数演化追踪
  Exp4: 加权投票 vs 等权投票

所有实验使用 Mock LLM，确保可控性和可重复性。

运行方式:
  python experiment.py              # 运行全部实验
  python experiment.py --exp 1      # 只运行实验1
  python experiment.py --exp 2      # 只运行实验2
  python experiment.py --exp 3      # 只运行实验3
  python experiment.py --exp 4      # 只运行实验4
"""

import sys
import os
import time
import json
import random
import argparse
import statistics
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict

# 确保能导入项目模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents import create_agents, Agent
from network import Network
from consensus import BFT4Agent
from llm_new import LLMCaller, LatencyAwareLLMCaller
from did_registry import DIDRegistry
from behavior_log import BehaviorLog
from reputation import ReputationSystem
from incentive import IncentiveSystem


# ============================================================
# 通用工具
# ============================================================

def create_math_tasks(n: int, seed: int = 42) -> List[Dict]:
    """生成数学任务（带正确答案，确保答案为整数避免格式问题）"""
    rng = random.Random(seed)
    tasks = []
    ops = ['+', '-', '*']  # 只用整数运算，避免浮点数格式问题
    for i in range(n):
        op = rng.choice(ops)
        if op == '+':
            a, b = rng.randint(1, 200), rng.randint(1, 200)
            answer = a + b
        elif op == '-':
            a, b = rng.randint(50, 300), rng.randint(1, 50)
            answer = a - b
        elif op == '*':
            a, b = rng.randint(2, 30), rng.randint(2, 30)
            answer = a * b
        tasks.append({
            "id": f"task_{i:04d}",
            "content": f"{a} {op} {b} = ?",
            "type": "math",
            "answer": str(answer),
        })
    return tasks


@dataclass
class ExperimentConfig:
    """实验配置"""
    num_agents: int = 7
    malicious_ratio: float = 0.2
    num_rounds: int = 50
    timeout: float = 10.0
    max_retries: int = 3
    seed: int = 42
    # 激励参数
    enable_did: bool = True
    enable_reputation: bool = True
    enable_incentive: bool = True
    enable_weighted_voting: bool = True
    alpha: float = 0.05
    beta: float = 0.3
    # LLM 后端配置
    llm_backend: str = "mock"           # mock | realistic | qwen | zhipu | openai | custom
    llm_api_config: Dict = field(default_factory=dict)   # 真实 LLM 的 API 参数
    latency_profile: str = "medium"     # fast | medium | slow (仅 realistic 模式)


@dataclass
class RoundResult:
    """单轮结果"""
    round_idx: int
    task_content: str = ""
    correct_answer: str = ""
    success: bool = False
    answer: str = ""
    answer_correct: bool = False
    view_changes: int = 0
    total_time: float = 0.0
    decision: str = ""
    # 投票统计
    y_count: int = 0
    n_count: int = 0
    y_weight: float = 0.0
    n_weight: float = 0.0
    # 信誉快照 {agent_id: float}
    reputation_snapshot: Dict = field(default_factory=dict)
    # 恶意节点被识别的次数
    malicious_detected: int = 0
    # === 延迟数据 ===
    llm_latency: Dict = field(default_factory=dict)    # LLM 调用延迟统计
    phase_times: Dict = field(default_factory=dict)     # 共识各阶段耗时 (pre_prepare/prepare/commit)


@dataclass
class ExperimentResult:
    """实验结果"""
    experiment_name: str = ""
    config: Dict = field(default_factory=dict)
    rounds: List[RoundResult] = field(default_factory=list)
    # 汇总指标
    summary: Dict = field(default_factory=dict)


def run_single_round(
    bft: BFT4Agent,
    task: Dict,
    agents: List[Agent],
    reputation_system: Optional[ReputationSystem],
    llm_wrapper: Optional[LatencyAwareLLMCaller] = None,
) -> RoundResult:
    """运行单轮共识并采集数据（含延迟统计）"""
    # 重置轮次级延迟跟踪
    if llm_wrapper:
        llm_wrapper.reset_round()

    result = bft.run(task)

    # 数值比较答案正确性（避免 "30" vs "30.0" 格式问题）
    try:
        answer_val = float(result.get("answer", ""))
        correct_val = float(task.get("answer", ""))
        is_correct = abs(answer_val - correct_val) < 0.001
    except (ValueError, TypeError):
        is_correct = False

    rr = RoundResult(
        round_idx=0,
        task_content=task["content"],
        correct_answer=task.get("answer", ""),
        success=result["success"],
        answer=result.get("answer", ""),
        answer_correct=is_correct,
        view_changes=result.get("view_changes", 0),
        total_time=result.get("total_time", 0.0),
        decision=result.get("decision", ""),
    )

    # 采集信誉快照
    if reputation_system:
        rr.reputation_snapshot = reputation_system.get_all_reputations()

    # 统计恶意节点被识别的情况（信誉下降的恶意节点数）
    malicious_agents = [a for a in agents if a.is_malicious]
    rr.malicious_detected = sum(
        1 for a in malicious_agents
        if a.reputation < 0.9
    )

    # 采集延迟数据
    if llm_wrapper:
        rr.llm_latency = llm_wrapper.get_round_stats()
    rr.phase_times = result.get("phase_times", {})

    return rr


def build_system(config: ExperimentConfig) -> Dict:
    """构建完整系统（支持多种 LLM 后端）"""
    # === 创建 LLM ===
    if config.llm_backend == "realistic":
        # 真实延迟模拟
        raw_llm = LLMCaller(
            backend="realistic",
            accuracy=1.0,
            profile=config.latency_profile,
        )
    elif config.llm_backend == "mock":
        raw_llm = LLMCaller(backend="mock", accuracy=1.0)
    else:
        # 真实 LLM 后端 (qwen/zhipu/openai/custom)
        raw_llm = LLMCaller(backend=config.llm_backend, **config.llm_api_config)

    # 包装延迟感知调用器
    llm = LatencyAwareLLMCaller(raw_llm)

    did_registry = DIDRegistry(min_stake=100.0) if config.enable_did else None
    behavior_log = BehaviorLog()
    reputation_system = ReputationSystem(
        did_registry=did_registry,
        behavior_log=behavior_log,
        alpha=config.alpha,
        beta=config.beta,
    ) if config.enable_reputation else None
    incentive_system = IncentiveSystem(
        did_registry=did_registry,
        reputation_system=reputation_system,
    ) if config.enable_incentive else None

    agents = create_agents(
        num_agents=config.num_agents,
        malicious_ratio=config.malicious_ratio,
        llm_caller=llm,
        did_registry=did_registry,
        behavior_log=behavior_log,
        stake_amount=200.0,
    )

    if reputation_system:
        reputation_system.initialize(agents)

    # 真实 LLM / realistic 模式下需要更长超时
    timeout = config.timeout
    if config.llm_backend in ("realistic", "qwen", "zhipu", "openai", "custom"):
        timeout = max(timeout, 60.0)

    network = Network(delay_range=(5, 30), packet_loss=0.0)
    for agent in agents:
        network.register(agent)

    bft = BFT4Agent(
        agents=agents,
        network=network,
        timeout=timeout,
        max_retries=config.max_retries,
        did_registry=did_registry,
        reputation_system=reputation_system,
        behavior_log=behavior_log,
        incentive_system=incentive_system,
        enable_weighted_voting=config.enable_weighted_voting,
    )

    return {
        "agents": agents,
        "bft": bft,
        "did_registry": did_registry,
        "behavior_log": behavior_log,
        "reputation_system": reputation_system,
        "incentive_system": incentive_system,
        "llm_wrapper": llm,   # 延迟感知调用器
    }


# ============================================================
# Exp1: 有激励 vs 无激励（长期运行对比）
# ============================================================

def run_experiment1(num_rounds: int = 50) -> Dict:
    """
    实验1: 有无激励系统长期对比

    Group A: 完整系统（DID + 信誉 + 激励 + 加权投票）
    Group B: 无激励（关闭信誉、激励、加权投票，即原始 PBFT）

    对比指标:
    - 共识成功率
    - 答案正确率（最终答案是否正确）
    - 恶意节点被正确识别的数量
    - 视图切换次数（反映系统效率）
    - 平均共识延迟
    """
    print("\n" + "=" * 70)
    print("  实验1: 有激励 vs 无激励 — 长期运行对比")
    print("=" * 70)

    tasks = create_math_tasks(num_rounds, seed=42)

    # --- Group A: 完整系统 ---
    print("\n>>> Group A: 完整系统（DID + 信誉 + 激励 + 加权投票）")
    cfg_a = ExperimentConfig(
        num_agents=7, malicious_ratio=0.2,
        num_rounds=num_rounds,
        enable_did=True, enable_reputation=True,
        enable_incentive=True, enable_weighted_voting=True,
    )
    sys_a = build_system(cfg_a)
    results_a = []

    for i, task in enumerate(tasks):
        rr = run_single_round(
            sys_a["bft"], task, sys_a["agents"], sys_a["reputation_system"],
            llm_wrapper=sys_a["llm_wrapper"],
        )
        rr.round_idx = i
        results_a.append(rr)
        if sys_a["reputation_system"]:
            sys_a["reputation_system"].sync_to_agents(sys_a["agents"])
        if (i + 1) % 10 == 0:
            print(f"  [Group A] 完成 {i+1}/{num_rounds} 轮")

    # --- Group B: 无激励系统 ---
    print("\n>>> Group B: 无激励系统（原始 PBFT）")
    cfg_b = ExperimentConfig(
        num_agents=7, malicious_ratio=0.2,
        num_rounds=num_rounds,
        enable_did=False, enable_reputation=False,
        enable_incentive=False, enable_weighted_voting=False,
    )
    sys_b = build_system(cfg_b)
    results_b = []

    for i, task in enumerate(tasks):
        rr = run_single_round(
            sys_b["bft"], task, sys_b["agents"], sys_b["reputation_system"],
            llm_wrapper=sys_b["llm_wrapper"],
        )
        rr.round_idx = i
        results_b.append(rr)
        if (i + 1) % 10 == 0:
            print(f"  [Group B] 完成 {i+1}/{num_rounds} 轮")

    # 汇总
    summary = {
        "group_a": _compute_summary(results_a, sys_a["agents"], "有激励"),
        "group_b": _compute_summary(results_b, sys_b["agents"], "无激励"),
        "reputation_trajectory_a": _extract_reputation_trajectory(results_a),
    }

    _print_exp1_summary(summary, results_a, results_b)

    return {
        "experiment": "exp1_incentive_comparison",
        "rounds": num_rounds,
        "summary": summary,
        "group_a_rounds": [_round_to_dict(r) for r in results_a],
        "group_b_rounds": [_round_to_dict(r) for r in results_b],
    }


# ============================================================
# Exp2: 不同恶意比例下的鲁棒性
# ============================================================

def run_experiment2(rounds_per_ratio: int = 20) -> Dict:
    """
    实验2: 不同恶意节点比例下的系统鲁棒性

    测试 malicious_ratio 从 0.0 到 0.4（步长0.05）
    每个比例运行 rounds_per_ratio 轮

    对比: 有激励系统 vs 无激励系统
    """
    print("\n" + "=" * 70)
    print("  实验2: 不同恶意节点比例下的鲁棒性")
    print("=" * 70)

    ratios = [round(x * 0.05, 2) for x in range(0, 9)]  # 0.0, 0.05, ..., 0.40
    tasks = create_math_tasks(rounds_per_ratio, seed=123)

    results_by_ratio = {"with_incentive": {}, "without_incentive": {}}

    for ratio in ratios:
        n_agents = 7
        # 确保 n >= 3f+1
        f = int(n_agents * ratio)
        if n_agents < 3 * f + 1 and ratio > 0:
            print(f"  跳过 ratio={ratio:.2f} (n={n_agents} < 3f+1={3*f+1})")
            continue

        print(f"\n--- 恶意比例: {ratio:.0%} ({int(n_agents*ratio)}/{n_agents} 节点) ---")

        # 有激励
        cfg_a = ExperimentConfig(
            num_agents=n_agents, malicious_ratio=ratio,
            num_rounds=rounds_per_ratio,
            enable_did=True, enable_reputation=True,
            enable_incentive=True, enable_weighted_voting=True,
        )
        sys_a = build_system(cfg_a)
        round_results_a = []
        for i, task in enumerate(tasks):
            rr = run_single_round(sys_a["bft"], task, sys_a["agents"], sys_a["reputation_system"],
                                  llm_wrapper=sys_a["llm_wrapper"])
            rr.round_idx = i
            round_results_a.append(rr)
            if sys_a["reputation_system"]:
                sys_a["reputation_system"].sync_to_agents(sys_a["agents"])
        results_by_ratio["with_incentive"][str(ratio)] = _compute_summary(round_results_a, sys_a["agents"], f"有激励-{ratio:.0%}")

        # 无激励
        cfg_b = ExperimentConfig(
            num_agents=n_agents, malicious_ratio=ratio,
            num_rounds=rounds_per_ratio,
            enable_did=False, enable_reputation=False,
            enable_incentive=False, enable_weighted_voting=False,
        )
        sys_b = build_system(cfg_b)
        round_results_b = []
        for i, task in enumerate(tasks):
            rr = run_single_round(sys_b["bft"], task, sys_b["agents"], sys_b["reputation_system"],
                                  llm_wrapper=sys_b["llm_wrapper"])
            rr.round_idx = i
            round_results_b.append(rr)
        results_by_ratio["without_incentive"][str(ratio)] = _compute_summary(round_results_b, sys_b["agents"], f"无激励-{ratio:.0%}")

    _print_exp2_summary(results_by_ratio, ratios)

    return {
        "experiment": "exp2_robustness",
        "results": results_by_ratio,
    }


# ============================================================
# Exp3: 信誉演化追踪
# ============================================================

def run_experiment3(num_rounds: int = 60) -> Dict:
    """
    实验3: 不同类型节点的信誉演化轨迹

    模拟三种节点:
    1. 诚实节点（始终正确投票）
    2. 恶意节点（始终投N/支持错误）
    3. 摇摆节点（前30轮诚实，后面变恶意）

    追踪每个节点的信誉分数变化
    """
    print("\n" + "=" * 70)
    print("  实验3: 信誉演化追踪（诚实/恶意/摇摆节点）")
    print("=" * 70)

    tasks = create_math_tasks(num_rounds, seed=99)

    cfg = ExperimentConfig(
        num_agents=7, malicious_ratio=0.2,  # 只标记前2个为恶意
        num_rounds=num_rounds,
        enable_did=True, enable_reputation=True,
        enable_incentive=True, enable_weighted_voting=True,
    )
    sys_obj = build_system(cfg)
    agents = sys_obj["agents"]
    rep_sys = sys_obj["reputation_system"]

    # 标记节点类型（用于后续分析）
    # agents[0], agents[1] 是恶意的
    # agents[2] 标记为摇摆（将在中途改变行为）
    node_types = {}
    for i, a in enumerate(agents):
        if a.is_malicious:
            node_types[a.id] = "malicious"
        elif i == 2:
            node_types[a.id] = "swinging"  # 摇摆节点
        else:
            node_types[a.id] = "honest"

    print(f"  节点类型: {node_types}")

    # 追踪每轮信誉
    reputation_history = {a.id: [1.0] for a in agents}
    swing_turn_point = num_rounds // 2  # 摇摆节点在中间变恶意

    for i, task in enumerate(tasks):
        # 摇摆节点行为切换
        if i >= swing_turn_point:
            agents[2].is_malicious = True
            agents[2].malicious_peers = [a.id for a in agents if a.is_malicious and a.id != agents[2].id]

        rr = run_single_round(sys_obj["bft"], task, agents, rep_sys,
                              llm_wrapper=sys_obj["llm_wrapper"])
        rr.round_idx = i

        if rep_sys:
            rep_sys.sync_to_agents(agents)
            for a in agents:
                reputation_history[a.id].append(a.reputation)

        if (i + 1) % 15 == 0:
            reps = {a.id: f"{a.reputation:.4f}" for a in agents}
            print(f"  第{i+1}轮信誉: {reps}")

    _print_exp3_summary(reputation_history, node_types, swing_turn_point)

    return {
        "experiment": "exp3_reputation_trajectory",
        "node_types": node_types,
        "swing_turn_point": swing_turn_point,
        "reputation_history": reputation_history,
    }


# ============================================================
# Exp4: 加权投票 vs 等权投票
# ============================================================

def run_experiment4(num_rounds: int = 40) -> Dict:
    """
    实验4: 加权投票 vs 等权投票效果对比

    关键指标:
    - 恶意提案通过率（越低越好）
    - 正确提案被否决率（越低越好）
    - 共识效率
    """
    print("\n" + "=" * 70)
    print("  实验4: 加权投票 vs 等权投票")
    print("=" * 70)

    tasks = create_math_tasks(num_rounds, seed=77)

    # --- 加权投票 ---
    print("\n>>> 加权投票模式")
    cfg_a = ExperimentConfig(
        num_agents=7, malicious_ratio=0.25,
        num_rounds=num_rounds,
        enable_did=True, enable_reputation=True,
        enable_incentive=True, enable_weighted_voting=True,
    )
    sys_a = build_system(cfg_a)
    results_weighted = []
    for i, task in enumerate(tasks):
        rr = run_single_round(sys_a["bft"], task, sys_a["agents"], sys_a["reputation_system"],
                              llm_wrapper=sys_a["llm_wrapper"])
        rr.round_idx = i
        results_weighted.append(rr)
        if sys_a["reputation_system"]:
            sys_a["reputation_system"].sync_to_agents(sys_a["agents"])
        if (i + 1) % 10 == 0:
            print(f"  [加权] 完成 {i+1}/{num_rounds} 轮")

    # --- 等权投票（有信誉但不用于投票）---
    print("\n>>> 等权投票模式")
    cfg_b = ExperimentConfig(
        num_agents=7, malicious_ratio=0.25,
        num_rounds=num_rounds,
        enable_did=True, enable_reputation=True,
        enable_incentive=True, enable_weighted_voting=False,  # 关键区别
    )
    sys_b = build_system(cfg_b)
    results_equal = []
    for i, task in enumerate(tasks):
        rr = run_single_round(sys_b["bft"], task, sys_b["agents"], sys_b["reputation_system"],
                              llm_wrapper=sys_b["llm_wrapper"])
        rr.round_idx = i
        results_equal.append(rr)
        if sys_b["reputation_system"]:
            sys_b["reputation_system"].sync_to_agents(sys_b["agents"])
        if (i + 1) % 10 == 0:
            print(f"  [等权] 完成 {i+1}/{num_rounds} 轮")

    summary = {
        "weighted": _compute_summary(results_weighted, sys_a["agents"], "加权投票"),
        "equal": _compute_summary(results_equal, sys_b["agents"], "等权投票"),
        "weighted_trajectory": _extract_reputation_trajectory(results_weighted),
        "equal_trajectory": _extract_reputation_trajectory(results_equal),
    }

    _print_exp4_summary(summary, results_weighted, results_equal)

    return {
        "experiment": "exp4_weighted_voting",
        "summary": summary,
    }


# ============================================================
# 汇总计算
# ============================================================

def _compute_summary(results: List[RoundResult], agents: List[Agent], label: str) -> Dict:
    """计算一组实验的汇总指标"""
    total = len(results)
    if total == 0:
        return {}

    successes = [r for r in results if r.success]
    correct_answers = [r for r in results if r.answer_correct]
    # 正确答案率（在成功的轮次中）
    success_with_correct = [r for r in successes if r.answer_correct]

    # 分阶段统计（前半 vs 后半，观察学习效果）
    half = total // 2
    first_half = results[:half]
    second_half = results[half:]

    malicious_agents = [a for a in agents if a.is_malicious]

    return {
        "label": label,
        "total_rounds": total,
        # 核心指标
        "success_rate": len(successes) / total,
        "answer_accuracy": len(correct_answers) / total,
        "accuracy_when_success": len(success_with_correct) / len(successes) if successes else 0,
        # 效率指标
        "avg_view_changes": statistics.mean([r.view_changes for r in results]),
        "avg_time": statistics.mean([r.total_time for r in results]),
        "total_view_changes": sum(r.view_changes for r in results),
        # 阶段对比
        "first_half_success_rate": len([r for r in first_half if r.success]) / len(first_half) if first_half else 0,
        "second_half_success_rate": len([r for r in second_half if r.success]) / len(second_half) if second_half else 0,
        # 恶意节点指标
        "malicious_detected_avg": statistics.mean([r.malicious_detected for r in results]),
        "final_malicious_reputation": {
            a.id: a.reputation for a in malicious_agents
        },
        # 最终所有节点信誉
        "final_reputations": {a.id: a.reputation for a in agents},
        # === 延迟指标 ===
        "latency": _compute_latency_summary(results),
    }


def _extract_reputation_trajectory(results: List[RoundResult]) -> Dict[str, List[float]]:
    """提取信誉分数随轮次变化的轨迹"""
    trajectory = {}
    for rr in results:
        for aid, rep in rr.reputation_snapshot.items():
            if aid not in trajectory:
                trajectory[aid] = []
            trajectory[aid].append(rep)
    return trajectory


def _compute_latency_summary(results: List[RoundResult]) -> Dict:
    """计算延迟汇总统计"""
    # 过滤有延迟数据的轮次
    latency_rounds = [r for r in results if r.llm_latency]
    phase_rounds = [r for r in results if r.phase_times]

    summary = {}

    # LLM 延迟
    if latency_rounds:
        gen_avgs = [r.llm_latency["generate_avg"] for r in latency_rounds if "generate_avg" in r.llm_latency]
        val_avgs = [r.llm_latency["validate_avg"] for r in latency_rounds if "validate_avg" in r.llm_latency]
        llm_totals = [r.llm_latency["total_llm_time"] for r in latency_rounds if "total_llm_time" in r.llm_latency]
        if gen_avgs:
            summary["avg_generate_latency"] = statistics.mean(gen_avgs)
        if val_avgs:
            summary["avg_validate_latency"] = statistics.mean(val_avgs)
        if llm_totals:
            summary["avg_llm_total"] = statistics.mean(llm_totals)

    # 阶段延迟
    if phase_rounds:
        pp = [r.phase_times["pre_prepare"] for r in phase_rounds if "pre_prepare" in r.phase_times]
        prep = [r.phase_times["prepare"] for r in phase_rounds if "prepare" in r.phase_times]
        comm = [r.phase_times["commit"] for r in phase_rounds if "commit" in r.phase_times]
        if pp:
            summary["avg_pre_prepare"] = statistics.mean(pp)
        if prep:
            summary["avg_prepare"] = statistics.mean(prep)
        if comm:
            summary["avg_commit"] = statistics.mean(comm)

    return summary


def _round_to_dict(rr: RoundResult) -> Dict:
    return {
        "round": rr.round_idx,
        "success": rr.success,
        "answer_correct": rr.answer_correct,
        "view_changes": rr.view_changes,
        "time": rr.total_time,
        "decision": rr.decision,
        "y_count": rr.y_count,
        "n_count": rr.n_count,
        "reputation": rr.reputation_snapshot,
        "malicious_detected": rr.malicious_detected,
        "llm_latency": rr.llm_latency,
        "phase_times": rr.phase_times,
    }


# ============================================================
# 打印汇总
# ============================================================

def _print_exp1_summary(summary: Dict, results_a: List[RoundResult], results_b: List[RoundResult]):
    """打印实验1汇总"""
    print("\n" + "=" * 70)
    print("  实验1 结果汇总")
    print("=" * 70)
    print(f"{'指标':<25} {'有激励':>12} {'无激励':>12} {'差异':>12}")
    print("-" * 65)

    a, b = summary["group_a"], summary["group_b"]
    metrics = [
        ("共识成功率", "success_rate"),
        ("答案正确率", "answer_accuracy"),
        ("成功时正确率", "accuracy_when_success"),
        ("平均视图切换", "avg_view_changes"),
        ("平均耗时(秒)", "avg_time"),
        ("前半段成功率", "first_half_success_rate"),
        ("后半段成功率", "second_half_success_rate"),
        ("恶意识别均值", "malicious_detected_avg"),
    ]

    for name, key in metrics:
        va, vb = a.get(key, 0), b.get(key, 0)
        if isinstance(va, float):
            diff = va - vb
            print(f"{name:<25} {va:>12.4f} {vb:>12.4f} {diff:>+12.4f}")
        else:
            print(f"{name:<25} {str(va):>12} {str(vb):>12}")

    # 最终信誉
    print(f"\n--- 最终信誉分数 ---")
    for aid, rep in a["final_reputations"].items():
        flag = " [M]" if aid in a.get("final_malicious_reputation", {}) else ""
        print(f"  有激励: {aid}: {rep:.4f}{flag}")
    for aid, rep in b["final_reputations"].items():
        flag = " [M]" if aid in b.get("final_malicious_reputation", {}) else ""
        print(f"  无激励: {aid}: {rep:.4f}{flag}")


def _print_exp2_summary(results: Dict, ratios: List[float]):
    """打印实验2汇总"""
    print("\n" + "=" * 70)
    print("  实验2 结果汇总 — 鲁棒性")
    print("=" * 70)
    print(f"{'恶意比例':<10} {'有激励成功率':>14} {'无激励成功率':>14} {'有激励正确率':>14} {'无激励正确率':>14}")
    print("-" * 70)

    for ratio in ratios:
        key = str(round(ratio, 2))
        a = results["with_incentive"].get(key, {})
        b = results["without_incentive"].get(key, {})
        if not a:
            continue
        print(f"{ratio:>8.0%}  {a.get('success_rate', 0):>14.4f} {b.get('success_rate', 0):>14.4f} "
              f"{a.get('answer_accuracy', 0):>14.4f} {b.get('answer_accuracy', 0):>14.4f}")


def _print_exp3_summary(reputation_history: Dict, node_types: Dict, swing_point: int):
    """打印实验3汇总"""
    print("\n" + "=" * 70)
    print("  实验3 结果汇总 — 信誉演化")
    print("=" * 70)

    print(f"\n摇摆节点切换点: 第 {swing_point} 轮")
    print(f"\n{'节点ID':<12} {'类型':<12} {'初始信誉':>10} {'最终信誉':>10} {'最低信誉':>10} {'变化趋势':>15}")
    print("-" * 75)

    for aid, hist in reputation_history.items():
        ntype = node_types.get(aid, "unknown")
        initial = hist[0] if hist else 1.0
        final = hist[-1] if hist else 1.0
        lowest = min(hist) if hist else 1.0
        # 简单趋势判断
        if len(hist) >= 10:
            first_5_avg = statistics.mean(hist[:5])
            last_5_avg = statistics.mean(hist[-5:])
            trend = "上升 ↑" if last_5_avg > first_5_avg + 0.01 else ("下降 ↓" if last_5_avg < first_5_avg - 0.01 else "稳定 →")
        else:
            trend = "N/A"
        print(f"{aid:<12} {ntype:<12} {initial:>10.4f} {final:>10.4f} {lowest:>10.4f} {trend:>15}")

    # 摇摆节点分析
    swinger_id = [aid for aid, t in node_types.items() if t == "swinging"]
    if swinger_id:
        sid = swinger_id[0]
        hist = reputation_history[sid]
        pre_swing = hist[:swing_point + 1]
        post_swing = hist[swing_point:]
        print(f"\n--- 摇摆节点 {sid} 分析 ---")
        print(f"  切换前平均信誉: {statistics.mean(pre_swing):.4f}")
        print(f"  切换后平均信誉: {statistics.mean(post_swing):.4f}")
        print(f"  信誉恢复速度: 需要观察后续变化")


def _print_exp4_summary(summary: Dict, results_w: List[RoundResult], results_e: List[RoundResult]):
    """打印实验4汇总"""
    print("\n" + "=" * 70)
    print("  实验4 结果汇总 — 加权 vs 等权")
    print("=" * 70)

    w, e = summary["weighted"], summary["equal"]
    print(f"{'指标':<25} {'加权投票':>12} {'等权投票':>12} {'差异':>12}")
    print("-" * 65)

    metrics = [
        ("共识成功率", "success_rate"),
        ("答案正确率", "answer_accuracy"),
        ("平均视图切换", "avg_view_changes"),
        ("平均耗时(秒)", "avg_time"),
        ("前半段成功率", "first_half_success_rate"),
        ("后半段成功率", "second_half_success_rate"),
    ]

    for name, key in metrics:
        vw, ve = w.get(key, 0), e.get(key, 0)
        if isinstance(vw, float):
            diff = vw - ve
            print(f"{name:<25} {vw:>12.4f} {ve:>12.4f} {diff:>+12.4f}")


# ============================================================
# Exp5: 端到端延迟分析（真实 LLM 延迟模拟）
# ============================================================

def run_experiment5(num_rounds: int = 10, latency_profile: str = "all") -> Dict:
    """
    实验5: 端到端延迟分析

    使用 RealisticMockLLM（对数正态延迟分布）模拟真实 LLM API 条件，
    测量 BFT4Agent 共识在不同延迟档位下的表现。

    子实验:
    - 5a: 不同延迟档位 (fast/medium/slow) + 完整激励系统
    - 5b: 激励系统额外开销 (medium 档位, 有激励 vs 无激励)

    关键指标:
    - 端到端共识延迟
    - LLM 调用延迟分布 (generate / validate)
    - 阶段耗时 (pre-prepare / prepare / commit)
    - 协议开销 = 总延迟 - LLM 延迟
    """
    print("\n" + "=" * 70)
    print("  实验5: 端到端延迟分析（真实 LLM 延迟模拟）")
    print("=" * 70)

    tasks = create_math_tasks(num_rounds, seed=555)

    # === 5a: 不同延迟档位 ===
    profiles = ["fast", "medium", "slow"] if latency_profile == "all" else [latency_profile]
    results_by_profile = {}

    for profile in profiles:
        print(f"\n>>> 5a: 延迟档位 = {profile}（有激励）")
        cfg = ExperimentConfig(
            num_agents=7, malicious_ratio=0.2,
            num_rounds=num_rounds,
            llm_backend="realistic",
            latency_profile=profile,
            enable_did=True, enable_reputation=True,
            enable_incentive=True, enable_weighted_voting=True,
        )
        sys_obj = build_system(cfg)
        round_results = []

        for i, task in enumerate(tasks):
            rr = run_single_round(
                sys_obj["bft"], task, sys_obj["agents"],
                sys_obj["reputation_system"],
                llm_wrapper=sys_obj["llm_wrapper"],
            )
            rr.round_idx = i
            round_results.append(rr)
            if sys_obj["reputation_system"]:
                sys_obj["reputation_system"].sync_to_agents(sys_obj["agents"])

        # 获取 LLM 延迟分布数据
        llm_dist = sys_obj["llm_wrapper"].get_all_latencies()

        results_by_profile[profile] = {
            "rounds": [_round_to_dict(r) for r in round_results],
            "summary": _compute_summary(round_results, sys_obj["agents"], f"{profile}+有激励"),
            "llm_distribution": {
                "generate_mean": statistics.mean(llm_dist["generate_latencies"]) if llm_dist["generate_latencies"] else 0,
                "generate_p50": sorted(llm_dist["generate_latencies"])[len(llm_dist["generate_latencies"])//2] if llm_dist["generate_latencies"] else 0,
                "generate_p95": sorted(llm_dist["generate_latencies"])[int(len(llm_dist["generate_latencies"])*0.95)] if len(llm_dist["generate_latencies"]) > 1 else 0,
                "validate_mean": statistics.mean(llm_dist["validate_latencies"]) if llm_dist["validate_latencies"] else 0,
                "validate_p50": sorted(llm_dist["validate_latencies"])[len(llm_dist["validate_latencies"])//2] if llm_dist["validate_latencies"] else 0,
                "validate_p95": sorted(llm_dist["validate_latencies"])[int(len(llm_dist["validate_latencies"])*0.95)] if len(llm_dist["validate_latencies"]) > 1 else 0,
                "generate_latencies": llm_dist["generate_latencies"],
                "validate_latencies": llm_dist["validate_latencies"],
            },
        }
        print(f"  [{profile}] 完成 {num_rounds} 轮")

    # === 5b: 激励系统额外开销 (medium 档位) ===
    print(f"\n>>> 5b: 激励系统额外开销（medium 档位）")

    # 有激励
    cfg_with = ExperimentConfig(
        num_agents=7, malicious_ratio=0.2,
        num_rounds=num_rounds,
        llm_backend="realistic",
        latency_profile="medium",
        enable_did=True, enable_reputation=True,
        enable_incentive=True, enable_weighted_voting=True,
    )
    sys_with = build_system(cfg_with)
    results_with = []
    for i, task in enumerate(tasks):
        rr = run_single_round(
            sys_with["bft"], task, sys_with["agents"],
            sys_with["reputation_system"],
            llm_wrapper=sys_with["llm_wrapper"],
        )
        rr.round_idx = i
        results_with.append(rr)
        if sys_with["reputation_system"]:
            sys_with["reputation_system"].sync_to_agents(sys_with["agents"])

    # 无激励
    cfg_without = ExperimentConfig(
        num_agents=7, malicious_ratio=0.2,
        num_rounds=num_rounds,
        llm_backend="realistic",
        latency_profile="medium",
        enable_did=False, enable_reputation=False,
        enable_incentive=False, enable_weighted_voting=False,
    )
    sys_without = build_system(cfg_without)
    results_without = []
    for i, task in enumerate(tasks):
        rr = run_single_round(
            sys_without["bft"], task, sys_without["agents"],
            sys_without["reputation_system"],
            llm_wrapper=sys_without["llm_wrapper"],
        )
        rr.round_idx = i
        results_without.append(rr)

    overhead_comparison = {
        "with_incentive": _compute_summary(results_with, sys_with["agents"], "有激励"),
        "without_incentive": _compute_summary(results_without, sys_without["agents"], "无激励"),
    }

    _print_exp5_summary(results_by_profile, overhead_comparison)

    return {
        "experiment": "exp5_latency_analysis",
        "results_by_profile": {k: {kk: vv for kk, vv in v.items() if kk != "rounds"}
                               for k, v in results_by_profile.items()},
        "profile_rounds": {k: v["rounds"] for k, v in results_by_profile.items()},
        "overhead_comparison": overhead_comparison,
    }


def _print_exp5_summary(results_by_profile: Dict, overhead: Dict):
    """打印实验5汇总"""
    print("\n" + "=" * 70)
    print("  实验5 结果汇总 — 端到端延迟分析")
    print("=" * 70)

    # 5a: 各档位概览
    print(f"\n--- 5a: 不同延迟档位（有激励系统）---")
    print(f"{'档位':<10} {'成功率':>8} {'正确率':>8} {'总延迟':>10} {'LLM延迟':>10} {'协议开销':>10} {'LLM占比':>10}")
    print("-" * 76)
    for profile, data in results_by_profile.items():
        s = data["summary"]
        lat = s.get("latency", {})
        avg_time = s.get("avg_time", 0)
        llm_total = lat.get("avg_llm_total", 0)
        overhead_time = avg_time - llm_total
        llm_ratio = (llm_total / avg_time * 100) if avg_time > 0 else 0
        print(f"{profile:<10} {s.get('success_rate', 0):>8.1%} {s.get('answer_accuracy', 0):>8.1%} "
              f"{avg_time:>9.2f}s {llm_total:>9.2f}s {overhead_time:>9.2f}s {llm_ratio:>9.1f}%")

    # LLM 延迟分布
    print(f"\n--- LLM 调用延迟分布 ---")
    print(f"{'档位':<10} {'Generate均值':>12} {'P50':>8} {'P95':>8} {'Validate均值':>12} {'P50':>8} {'P95':>8}")
    print("-" * 76)
    for profile, data in results_by_profile.items():
        d = data["llm_distribution"]
        print(f"{profile:<10} {d['generate_mean']:>11.3f}s {d['generate_p50']:>7.3f}s {d['generate_p95']:>7.3f}s "
              f"{d['validate_mean']:>11.3f}s {d['validate_p50']:>7.3f}s {d['validate_p95']:>7.3f}s")

    # 阶段耗时
    print(f"\n--- 阶段耗时分析 ---")
    print(f"{'档位':<10} {'Pre-Prepare':>12} {'Prepare':>12} {'Commit':>12} {'合计':>12}")
    print("-" * 62)
    for profile, data in results_by_profile.items():
        lat = data["summary"].get("latency", {})
        pp = lat.get("avg_pre_prepare", 0)
        prep = lat.get("avg_prepare", 0)
        comm = lat.get("avg_commit", 0)
        print(f"{profile:<10} {pp:>11.3f}s {prep:>11.3f}s {comm:>11.3f}s {pp+prep+comm:>11.3f}s")

    # 5b: 激励开销
    print(f"\n--- 5b: 激励系统额外开销（medium 档位）---")
    w = overhead["with_incentive"]
    wo = overhead["without_incentive"]
    print(f"{'指标':<25} {'有激励':>12} {'无激励':>12} {'差异':>12}")
    print("-" * 65)
    for name, key in [
        ("共识成功率", "success_rate"),
        ("答案正确率", "answer_accuracy"),
        ("平均总延迟(s)", "avg_time"),
    ]:
        vw, vwo = w.get(key, 0), wo.get(key, 0)
        if isinstance(vw, float):
            diff = vw - vwo
            print(f"{name:<25} {vw:>12.4f} {vwo:>12.4f} {diff:>+12.4f}")

    # 延迟对比
    wl = w.get("latency", {})
    wol = wo.get("latency", {})
    if wl or wol:
        for name, wkey in [
            ("LLM总延迟(s)", "avg_llm_total"),
            ("Pre-Prepare(s)", "avg_pre_prepare"),
            ("Prepare(s)", "avg_prepare"),
            ("Commit(s)", "avg_commit"),
        ]:
            vw = wl.get(wkey, 0)
            vwo = wol.get(wkey, 0)
            diff = vw - vwo
            print(f"{name:<25} {vw:>12.3f} {vwo:>12.3f} {diff:>+12.3f}")


# ============================================================
# 主入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="BFT4Agent 信誉/激励系统有效性实验")
    parser.add_argument("--exp", type=int, nargs="*", default=[1, 2, 3, 4],
                        help="要运行的实验编号 (1-5)，默认全部运行")
    parser.add_argument("--rounds", type=int, default=50,
                        help="每组的轮次数量（默认50）")
    parser.add_argument("--output", type=str, default="data/results/experiment_results.json",
                        help="结果输出文件路径")
    parser.add_argument("--profile", type=str, default="all",
                        help="Exp5 延迟档位: fast/medium/slow/all（默认 all）")
    args = parser.parse_args()

    output_path = args.output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # 增量加载已有结果（避免覆盖之前已完成的实验）
    all_results = {}
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                all_results = json.load(f)
            print(f"  已加载已有结果: {list(all_results.keys())}")
        except Exception:
            all_results = {}

    def _save_incremental():
        """增量保存结果到文件"""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2, default=str)

    for exp_num in args.exp:
        key = f"exp{exp_num}"
        if key in all_results:
            print(f"  实验{exp_num}已有结果，跳过（删除文件或删除key重跑）")
            continue

        t0 = time.time()
        if exp_num == 1:
            result = run_experiment1(num_rounds=args.rounds)
        elif exp_num == 2:
            result = run_experiment2(rounds_per_ratio=min(args.rounds, 20))
        elif exp_num == 3:
            result = run_experiment3(num_rounds=args.rounds)
        elif exp_num == 4:
            result = run_experiment4(num_rounds=args.rounds)
        elif exp_num == 5:
            result = run_experiment5(num_rounds=min(args.rounds, 15),
                                     latency_profile=args.profile)
        else:
            print(f"未知实验编号: {exp_num}")
            continue

        elapsed = time.time() - t0
        print(f"\n  实验{exp_num}完成，耗时 {elapsed:.1f} 秒")
        all_results[key] = result

        # 每完成一个实验就保存一次
        _save_incremental()
        print(f"  结果已增量保存到: {output_path}")

    return all_results


if __name__ == "__main__":
    # 禁用 BFT 的详细日志，只保留实验输出
    import logging
    logging.getLogger().setLevel(logging.WARNING)

    # 通过重定向减少噪音输出
    import io
    original_stdout = sys.stdout

    class QuietMode:
        """过滤掉详细的 BFT 日志，只保留实验级别的输出"""
        def __init__(self, orig):
            self.orig = orig
            self.skip_patterns = [
                "[PROPOSE DEBUG]", "[PREPARE]", "[COMMIT]", "[VIEW-CHANGE]",
                "[状态重置]", "[Leader提案内容]", "[恶意Leader", "[恶意Backup",
                "[DID] 注册成功", "[DID] 罚没", "[DID] 暂停", "[DID] 吊销",
                "[恶意节点配置]", "[信誉系统]", "[验证]", "[MockLLM]",
                "broadcast", "Leader不参与", "正在评价", "评价结果",
                "创建PREPARE", "创建COMMIT", "等待", "额外等待",
                "分发", "收到", "达到", "广播", "[后处理]", "[激励]",
                "[信誉-DID联动]", "投N反对", "投Y支持", "使用",
            ]

        def write(self, text):
            for p in self.skip_patterns:
                if p in text:
                    return len(text)
            self.orig.write(text)

        def flush(self):
            self.orig.flush()

    sys.stdout = QuietMode(original_stdout)
    try:
        results = main()
    finally:
        sys.stdout = original_stdout

    print("\n全部实验完成!")
