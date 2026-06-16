"""
BFT4Agent Demo - 主入口

快速演示BFT4Agentconsensus流程
集成 DID 身份系统、信誉系统、行为日志、激励层
"""

import sys
import time
import json
from config import load_config
from agents import create_agents
from network import Network
from consensus import BFT4Agent
from llm_new import LLMCaller
from tasks import TaskLoader

# 新增模块
from did_registry import DIDRegistry
from behavior_log import BehaviorLog
from reputation import ReputationSystem
from incentive import IncentiveSystem


def print_header(title: str):
    """打印标题"""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def print_config(config):
    """打印config"""
    print("\n=== config ===")
    print(f"Agent数量: {config['num_agents']}")
    print(f"maliciousnode比例: {config['malicious_ratio']:.1%}")
    print(f"LLM后端: {config['llm_backend']}")
    print(f"networkdelay: {config['network_delay']} ms")
    print(f"法定人数比例: {config['quorum_ratio']:.1%}")

    # 新增配置
    did_cfg = config.get("did", {})
    rep_cfg = config.get("reputation", {})
    inc_cfg = config.get("incentive", {})
    wv_cfg = config.get("weighted_voting", {})

    print(f"DID系统: {'启用' if did_cfg.get('enabled') else '禁用'}")
    print(f"信誉系统: {'启用' if rep_cfg.get('enabled') else '禁用'}")
    print(f"激励系统: {'启用' if inc_cfg.get('enabled') else '禁用'}")
    print(f"加权投票: {'启用' if wv_cfg.get('enabled') else '禁用'}")


def main():
    """主函数"""
    print_header("BFT4Agent v2.0 - 集成DID/信誉/激励层")

    # 加载config
    config = load_config()
    print_config(config)

    # ========== 1. 初始化 DID / 信誉 / 行为日志 / 激励系统 ==========
    did_cfg = config.get("did", {})
    rep_cfg = config.get("reputation", {})
    inc_cfg = config.get("incentive", {})
    wv_cfg = config.get("weighted_voting", {})

    # DID 注册表
    did_registry = None
    if did_cfg.get("enabled", True):
        did_registry = DIDRegistry(min_stake=did_cfg.get("min_stake", 100.0))
        print(f"\n[init] DID注册表已创建 (最低质押: {did_cfg.get('min_stake', 100.0)})")

    # 行为日志
    behavior_log = BehaviorLog()
    print(f"[init] 行为日志系统已创建")

    # 信誉系统
    reputation_system = None
    if rep_cfg.get("enabled", True):
        reputation_system = ReputationSystem(
            did_registry=did_registry,
            behavior_log=behavior_log,
            alpha=rep_cfg.get("alpha", 0.05),
            beta=rep_cfg.get("beta", 0.3),
            decay_factor=rep_cfg.get("decay_factor", 0.995),
            suspend_threshold=rep_cfg.get("suspend_threshold", 0.3),
            revoke_threshold=rep_cfg.get("revoke_threshold", 0.1),
        )
        print(f"[init] 信誉系统已创建 (alpha={rep_cfg.get('alpha', 0.05)}, beta={rep_cfg.get('beta', 0.3)})")

    # 激励系统
    incentive_system = None
    if inc_cfg.get("enabled", True):
        incentive_system = IncentiveSystem(
            did_registry=did_registry,
            reputation_system=reputation_system,
            behavior_log=behavior_log,
            initial_pool=inc_cfg.get("initial_pool", 10000.0),
        )
        print(f"[init] 激励系统已创建 (初始池: {inc_cfg.get('initial_pool', 10000.0)})")

    # ========== 2. 创建 LLM ==========
    print(f"\n[init] 创建LLM ({config['llm_backend']})...")

    backend = config["llm_backend"]
    llm_kwargs = {}

    if backend == "mock":
        llm_kwargs["accuracy"] = config.get("mock_accuracy", 0.85)
    else:
        api_config = config.get("llm_api_config", {}).get(backend, {})
        if api_config:
            if backend == "openai":
                llm_kwargs["api_key"] = api_config.get("api_key", "")
                if api_config.get("base_url"):
                    llm_kwargs["base_url"] = api_config["base_url"]
                llm_kwargs["model"] = api_config.get("model", "gpt-3.5-turbo")

            elif backend == "zhipu":
                llm_kwargs["api_key"] = api_config.get("api_key", "")
                llm_kwargs["model"] = api_config.get("model", "glm-4")

            elif backend == "qwen":
                import os
                llm_kwargs["api_key"] = api_config.get("api_key") or os.getenv("DASHSCOPE_API_KEY")
                llm_kwargs["app_id"] = api_config.get("app_id", "")
                llm_kwargs["enable_thinking"] = api_config.get("enable_thinking", False)

            elif backend == "custom":
                llm_kwargs["api_key"] = api_config.get("api_key", "")
                llm_kwargs["base_url"] = api_config.get("base_url", "")
                llm_kwargs["model"] = api_config.get("model", "custom-model")

            elif backend in ["tongyi", "wenxin", "xunfei", "claude"]:
                for key, value in api_config.items():
                    llm_kwargs[key] = value

    llm = LLMCaller(backend=backend, **llm_kwargs)

    # ========== 3. 创建 Agent（集成 DID 注册）==========
    num_malicious = int(config["num_agents"] * config["malicious_ratio"])
    print(f"\n[init] 创建 {config['num_agents']} 个Agent ({num_malicious} 个malicious)...")

    role_configs = config.get("agent_roles", [])
    random_assignment = config.get("assign_roles_randomly", True)

    agents = create_agents(
        num_agents=config["num_agents"],
        malicious_ratio=config["malicious_ratio"],
        llm_caller=llm,
        role_configs=role_configs,
        random_assignment=random_assignment,
        did_registry=did_registry,
        behavior_log=behavior_log,
        stake_amount=did_cfg.get("stake_amount", 200.0),
    )

    # 初始化信誉系统
    if reputation_system:
        reputation_system.initialize(agents)

    # 打印Agent信息（增强版）
    print("\n=== Agent列表（含DID和信誉）===")
    for agent in agents:
        malicious_flag = " [malicious]" if agent.is_malicious else ""
        specialty_name = agent.role_config.get("name", "通用")
        specialty = f"- {specialty_name}" if agent.role_config else ""
        did_str = agent.did if agent.did else "无DID"
        print(f"  {agent.id}: {specialty}, rep={agent.reputation:.2f}, weight={agent.voting_weight:.3f}, did={did_str}{malicious_flag}")

    # ========== 4. 创建网络 ==========
    print(f"\n[init] 创建P2Pnetwork...")
    network = Network(
        delay_range=config["network_delay"], packet_loss=config.get("packet_loss", 0.01)
    )

    for agent in agents:
        network.register(agent)

    # ========== 5. 创建 BFT 实例（集成所有新模块）==========
    print(f"[init] initBFT4Agent协议（集成DID/信誉/激励）...")
    bft = BFT4Agent(
        agents=agents,
        network=network,
        timeout=config["timeout"],
        max_retries=config["max_retries"],
        did_registry=did_registry,
        reputation_system=reputation_system,
        behavior_log=behavior_log,
        incentive_system=incentive_system,
        enable_weighted_voting=wv_cfg.get("enabled", True),
    )

    # ========== 6. 加载任务 ==========
    print_header("加载任务")

    try:
        task_loader = TaskLoader(config)
        tasks = task_loader.load()
    except Exception as e:
        print(f"\n[ERROR] 任务加载失败: {e}")
        print("\n[INFO] 使用默认任务（向后兼容）")
        tasks = [
            {"content": "2 + 2 = ?", "type": "math", "answer": "4"},
            {"content": "23 * 47 = ?", "type": "math", "answer": "1081"},
            {"content": "144 / 12 = ?", "type": "math", "answer": "12"},
        ]

    # ========== 7. 运行共识 ==========
    print_header("开始共识流程")

    results = []

    for i, task in enumerate(tasks, 1):
        print(f"\n{'=' * 60}")
        print(f"  Task {i}/{len(tasks)}: {task['content']}")
        print(f"{'=' * 60}")

        result = bft.run(task)
        results.append(result)

        # 同步信誉到 Agent
        if reputation_system:
            reputation_system.sync_to_agents(agents)

        time.sleep(0.1)

    # ========== 8. 输出完整报告 ==========
    print_header("实验结果统计")

    success_count = sum(1 for r in results if r["success"])
    total_time = sum(r["total_time"] for r in results)
    total_view_changes = sum(r["view_changes"] for r in results)

    print(f"总task数: {len(results)}")
    print(f"success: {success_count} ({success_count/len(results):.1%})")
    print(f"failed: {len(results) - success_count}")
    print(f"总time: {total_time:.2f}秒")
    print(f"平均time: {total_time/len(results):.2f}秒")
    print(f"总viewchange: {total_view_changes}次")

    # BFT 统计
    stats = bft.get_stats()
    print(f"\n=== BFT协议stats ===")
    for key, value in stats.items():
        print(f"{key}: {value}")

    # 网络统计
    net_stats = network.get_stats()
    print(f"\n=== networkstats ===")
    for key, value in net_stats.items():
        print(f"{key}: {value}")

    # DID 统计
    if did_registry:
        print(f"\n=== DID注册表统计 ===")
        did_stats = did_registry.get_stats()
        for k, v in did_stats.items():
            print(f"  {k}: {v}")

    # 信誉统计
    if reputation_system:
        print(f"\n=== 信誉系统统计 ===")
        rep_stats = reputation_system.get_stats()
        for k, v in rep_stats.items():
            print(f"  {k}: {v}")

        # 打印每个 Agent 的信誉和权重
        print(f"\n=== Agent信誉与权重 ===")
        for agent in agents:
            level = ReputationSystem.get_reputation_level(agent.reputation).value
            print(f"  {agent.id}: rep={agent.reputation:.4f} ({level}), weight={agent.voting_weight:.4f}, "
                  f"tasks={agent.tasks_participated}, success={agent.tasks_success}")

    # 激励统计
    if incentive_system:
        print(f"\n=== 激励系统统计 ===")
        inc_stats = incentive_system.get_stats()
        for k, v in inc_stats.items():
            print(f"  {k}: {v}")

        # 排行榜
        print(f"\n=== 贡献度排行榜 ===")
        lb = incentive_system.get_leaderboard()
        for rank, entry in enumerate(lb, 1):
            print(f"  #{rank} {entry['agent_id']}: score={entry['contribution_score']:.3f}, "
                  f"balance={entry['balance']:.2f}, rep={entry['reputation']:.4f}")

    # 行为日志统计
    if behavior_log:
        print(f"\n=== 行为日志统计 ===")
        bl_stats = behavior_log.get_stats()
        for k, v in bl_stats.items():
            print(f"  {k}: {v}")

        # 可疑行为检测
        print(f"\n=== 可疑行为检测 ===")
        for agent in agents:
            patterns = behavior_log.detect_suspicious_patterns(agent.id)
            if patterns["suspicions"]:
                print(f"  {agent.id}: suspicion_score={patterns['suspicion_score']:.2f}")
                for s in patterns["suspicions"]:
                    print(f"    [{s['severity']}] {s['description']}")

    # DID 注册表快照
    if did_registry:
        print(f"\n=== DID注册表快照 ===")
        snapshot = did_registry.get_registry_snapshot()
        for doc in snapshot:
            print(f"  {doc['did']}: status={doc['status']}, stake={doc['stake_amount']:.2f}, "
                  f"credentials={len(doc['credentials'])}")

    print("\n" + "=" * 60)
    print("  Demo complete!")
    print("=" * 60)

    return results


if __name__ == "__main__":
    try:
        results = main()
    except KeyboardInterrupt:
        print("\n\n[中断] 用户取消")
        sys.exit(0)
    except Exception as e:
        print(f"\n[错误] {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
