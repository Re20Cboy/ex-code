"""
简化的配置系统 - 只用一个字典
"""

import os
from pathlib import Path


def load_env_file():
    """
    加载.env文件（如果存在）

    从项目根目录或bft4agent-simple目录加载.env文件
    """
    # 可能的.env文件路径
    possible_paths = [
        Path(__file__).parent / ".env",  # bft4agent-simple/.env
        Path(__file__).parent.parent / ".env",  # 项目根目录/.env
    ]

    for env_path in possible_paths:
        if env_path.exists():
            try:
                with open(env_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        # 跳过注释和空行
                        if not line or line.startswith('#'):
                            continue
                        # 解析KEY=VALUE格式
                        if '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            # 只有当环境变量不存在时才设置
                            if key not in os.environ:
                                os.environ[key] = value
            except Exception as e:
                print(f"[WARNING] Failed to load {env_path}: {e}")


# 在加载配置前先加载.env文件
load_env_file()


# 默认配置
CONFIG = {
    # Agent配置
    "num_agents": 5,  # Agent数量（建议3-7个）
    "malicious_ratio": 0.2,  # 1/5 = 20%

    # Agent角色配置（通过prompt给不同agent分配专业领域）
    "agent_roles": [
        {
            "name": "数学专家",
            "specialty": "math",
            "system_prompt": "你是一位数学专家，擅长精确计算和数学推理。请认真分析问题，给出准确且精简的计算过程和答案。",
            "validation_style": "strict"  # 验证风格：strict（严格）、balanced（平衡）、lenient（宽松）
        },
        {
            "name": "逻辑分析师",
            "specialty": "logic",
            "system_prompt": "你是一位逻辑分析师，擅长分析问题的逻辑结构和推理链条。请准确且精简地检查推理过程是否严密，逻辑是否清晰。",
            "validation_style": "balanced"
        },
        {
            "name": "验证专家",
            "specialty": "verification",
            "system_prompt": "你是一位验证专家，擅长发现推理中的错误和漏洞。请准确且精简地检查答案的准确性和推理的合理性。",
            "validation_style": "strict"
        },
        {
            "name": "综合思考者",
            "specialty": "general",
            "system_prompt": "你是一位综合思考者，能够从多个角度分析问题。请全面考虑问题，给出准确且精简的答案。",
            "validation_style": "balanced"
        },
        {
            "name": "批判性思维者",
            "specialty": "critical",
            "system_prompt": "你是一位批判性思维者，善于质疑和深入思考。请对问题进行深入分析，不要轻易接受表面答案。",
            "validation_style": "strict"
        }
    ],
    "assign_roles_randomly": True,  # 是否随机分配角色（False则按顺序分配）

    # LLM配置
    "llm_backend": "qwen",  # mock | openai | zhipu | qwen | custom
    "mock_accuracy": 1.0,  # Mock LLM准确率（诚实节点100%生成正确答案）
    "api_timeout": 30,
    "single_task_mode": False,  # 单任务模式（True=单任务用于测试，False=多任务用于实验）

    # LLM API配置（用于真实LLM）
    "llm_api_config": {
        # OpenAI配置
        "openai": {
            "api_key": os.getenv("OPENAI_API_KEY", ""),
            "base_url": os.getenv("OPENAI_BASE_URL"),  # 可选：自定义端点（如代理）
            "model": "gpt-3.5-turbo",
        },
        # 智谱AI GLM配置
        "zhipu": {
            "api_key": os.getenv("ZHIPU_API_KEY", ""),
            "model": "glm-4.6",  # 可选：glm-4.7, glm-4-plus, glm-4-flash 等
        },
        # 阿里云千问配置
        "qwen": {
            "api_key": os.getenv("DASHSCOPE_API_KEY", ""),
            "app_id": os.getenv("QWEN_APP_ID", ""),
            "enable_thinking": False,  # 是否启用思考模式（用于深度思考模型）
        },
        # 自定义API配置（OpenAI兼容格式）
        "custom": {
            "api_key": os.getenv("CUSTOM_API_KEY", ""),
            "base_url": os.getenv("CUSTOM_BASE_URL", ""),  # API端点URL
            "model": os.getenv("CUSTOM_MODEL", ""),
        },
    },

    # 网络配置
    "network_delay": (10, 100),  # (min, max) in ms
    "packet_loss": 0.01,  # 1% 丢包率

    # 共识配置
    "timeout": 30.0,  # 超时时间（秒）- 增加到30秒以适应真实LLM API调用速度
    "max_retries": 3,  # 最大重试次数
    "quorum_ratio": 2.0 / 3.0,  # 法定人数比例

    # 任务配置
    "tasks": {
        "file": "math_tasks.json",  # 任务文件路径
        "dataset_name": "simple_math",  # 数据集名称
        "num_tasks": 3,  # 选择任务数量（null 表示全部）
        "shuffle": False,  # 是否打乱顺序
        "task_ids": None,  # 指定 task_id 列表（优先级高于 num_tasks）
    },

    # 实验配置
    "output_dir": "data/results",
    "save_intermediate": True,
    "random_seed": 42,

    # === DID 身份系统配置 ===
    "did": {
        "enabled": True,                # 是否启用 DID 系统
        "min_stake": 100.0,             # 最低质押金额
        "stake_amount": 200.0,          # 默认质押金额
        "stake_slash_ratio": 0.5,       # 罚没质押比例
    },

    # === 信誉系统配置 ===
    "reputation": {
        "enabled": True,                # 是否启用信誉系统
        "alpha": 0.05,                  # 奖励系数
        "beta": 0.3,                    # 惩罚系数（beta >> alpha，严打恶意）
        "decay_factor": 0.995,          # 自然衰减因子
        "suspend_threshold": 0.3,       # DID 暂停阈值
        "revoke_threshold": 0.1,        # DID 吊销阈值
    },

    # === 激励系统配置 ===
    "incentive": {
        "enabled": True,                # 是否启用激励系统
        "initial_pool": 10000.0,        # 初始激励池金额
        "base_proposal_reward": 10.0,   # Leader 基础提案奖励
        "base_validation_reward": 5.0,  # Backup 基础验证奖励
    },

    # === 加权投票配置 ===
    "weighted_voting": {
        "enabled": True,                # 是否启用加权投票
    },
}


def load_config(config_file=None):
    """
    加载配置

    Args:
        config_file: YAML配置文件路径（可选）

    Returns:
        配置字典
    """
    import yaml
    from copy import deepcopy

    config = deepcopy(CONFIG)

    if config_file:
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
                config.update(user_config)
        except FileNotFoundError:
            print(f"[WARNING] Config file not found: {config_file}")
            print(f"[INFO] Using default config")

    return config


def save_config(config, filename):
    """保存配置到YAML文件"""
    import yaml

    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False)


if __name__ == "__main__":
    # 测试配置加载
    config = load_config()
    print("=== BFT4Agent Configuration ===")
    for key, value in config.items():
        print(f"{key}: {value}")
