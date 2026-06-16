"""LLM统一调用接口

支持两种调用模式:
- LLMCaller: 基础调用器，支持多种后端
- LatencyAwareLLMCaller: 延迟感知包装器，记录每次调用的耗时
"""
import time
import threading
from typing import Dict, List, Tuple
from llm_modules import MockLLM, RealisticMockLLM, ZhipuLLM, OpenAILLM, QwenLLM, CustomLLM


class LLMCaller:
    def __init__(self, backend: str = "mock", **kwargs):
        self.backend = backend.lower()
        self.llm = self._create_llm(backend, **kwargs)

    def _create_llm(self, backend: str, **kwargs):
        backend = backend.lower()

        if backend == "mock":
            return MockLLM(accuracy=kwargs.get("accuracy", 0.85))

        elif backend == "realistic":
            return RealisticMockLLM(
                accuracy=kwargs.get("accuracy", 1.0),
                profile=kwargs.get("profile", "medium"),
            )

        elif backend == "zhipu":
            api_key = kwargs.get("api_key")
            if not api_key:
                raise ValueError("Zhipu requires api_key")
            return ZhipuLLM(api_key=api_key, model=kwargs.get("model", "glm-4.7"))

        elif backend == "openai":
            api_key = kwargs.get("api_key")
            if not api_key:
                raise ValueError("OpenAI requires api_key")
            return OpenAILLM(
                api_key=api_key,
                base_url=kwargs.get("base_url"),
                model=kwargs.get("model", "gpt-3.5-turbo")
            )

        elif backend == "qwen":
            api_key = kwargs.get("api_key")
            app_id = kwargs.get("app_id")
            if not app_id:
                raise ValueError("Qwen requires app_id")
            return QwenLLM(
                api_key=api_key,
                app_id=app_id,
                enable_thinking=kwargs.get("enable_thinking", False)
            )

        elif backend == "custom":
            api_key = kwargs.get("api_key")
            base_url = kwargs.get("base_url")
            if not api_key or not base_url:
                raise ValueError("Custom requires api_key and base_url")
            return CustomLLM(
                api_key=api_key,
                base_url=base_url,
                model=kwargs.get("model", "custom-model")
            )

        else:
            raise ValueError(f"Unknown backend: {backend}")

    def generate(self, question: str) -> Tuple[list, str]:
        return self.llm.generate(question)

    def validate(self, proposal: Dict) -> str:
        return self.llm.validate(proposal)

    def health_check(self) -> bool:
        return self.llm.health_check()


class LatencyAwareLLMCaller:
    """
    延迟感知 LLM 调用器

    包装任意 LLMCaller，透明地记录每次 generate/validate 调用的延迟。
    支持线程安全（使用锁保护内部记录）。

    用法:
        raw_llm = LLMCaller(backend="qwen", ...)
        llm = LatencyAwareLLMCaller(raw_llm)
        # 传给 agents 使用，和普通 LLMCaller 接口完全一致
        agents = create_agents(..., llm_caller=llm)
        # 共识后查询延迟统计
        stats = llm.get_round_stats()
    """

    def __init__(self, caller):
        """
        Args:
            caller: LLMCaller 实例（或任何有 generate/validate 方法的对象）
        """
        self.caller = caller
        self._lock = threading.Lock()
        self.call_history: List[Dict] = []   # 全局历史
        self._round_calls: List[Dict] = []   # 当前轮次

    def generate(self, question: str) -> Tuple[list, str]:
        t0 = time.time()
        result = self.caller.generate(question)
        latency = time.time() - t0
        with self._lock:
            record = {"type": "generate", "latency": latency, "timestamp": t0}
            self.call_history.append(record)
            self._round_calls.append(record)
        return result

    def validate(self, proposal: Dict) -> str:
        t0 = time.time()
        result = self.caller.validate(proposal)
        latency = time.time() - t0
        with self._lock:
            record = {"type": "validate", "latency": latency, "timestamp": t0}
            self.call_history.append(record)
            self._round_calls.append(record)
        return result

    def health_check(self) -> bool:
        return self.caller.health_check()

    def get_round_stats(self) -> Dict:
        """获取当前轮次的延迟统计"""
        with self._lock:
            calls = list(self._round_calls)
        if not calls:
            return {}
        gen = [c for c in calls if c["type"] == "generate"]
        val = [c for c in calls if c["type"] == "validate"]
        stats = {
            "generate_count": len(gen),
            "validate_count": len(val),
            "total_calls": len(calls),
        }
        if gen:
            lats = [c["latency"] for c in gen]
            stats["generate_total"] = sum(lats)
            stats["generate_avg"] = sum(lats) / len(lats)
            stats["generate_max"] = max(lats)
            stats["generate_min"] = min(lats)
        if val:
            lats = [c["latency"] for c in val]
            stats["validate_total"] = sum(lats)
            stats["validate_avg"] = sum(lats) / len(lats)
            stats["validate_max"] = max(lats)
            stats["validate_min"] = min(lats)
        stats["total_llm_time"] = sum(c["latency"] for c in calls)
        return stats

    def reset_round(self):
        """重置轮次级跟踪（每轮共识前调用）"""
        with self._lock:
            self._round_calls = []

    def get_all_latencies(self) -> Dict:
        """获取所有历史调用的延迟数据（用于分布分析）"""
        with self._lock:
            all_calls = list(self.call_history)
        gen = [c["latency"] for c in all_calls if c["type"] == "generate"]
        val = [c["latency"] for c in all_calls if c["type"] == "validate"]
        return {
            "generate_latencies": gen,
            "validate_latencies": val,
            "all_latencies": [c["latency"] for c in all_calls],
            "total_generate_calls": len(gen),
            "total_validate_calls": len(val),
        }

    def reset_all(self):
        """清空所有历史记录"""
        with self._lock:
            self.call_history = []
            self._round_calls = []