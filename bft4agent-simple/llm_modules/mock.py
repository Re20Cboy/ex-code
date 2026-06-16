"""Mock LLM - 用于测试

包含两种实现:
- MockLLM: 快速模拟（微秒级延迟），用于功能验证
- RealisticMockLLM: 真实延迟模拟（秒级），用于延迟分析实验
"""
import math
import random
import time
from typing import Dict, Tuple
from .base import BaseLLM


class MockLLM(BaseLLM):
    def __init__(self, accuracy: float = 0.85):
        self.accuracy = accuracy

    def generate(self, question: str) -> Tuple[list, str]:
        time.sleep(random.uniform(0.1, 0.5))
        reasoning, answer = self._solve_math(question)

        # 调试输出
        print(f"[MockLLM.generate] 输入问题: {repr(question)}")
        print(f"[MockLLM.generate] 解析结果: reasoning={reasoning}, answer={answer}")

        if random.random() > self.accuracy:
            old_answer = answer
            answer = str(int(answer) + random.randint(1, 10))
            print(f"[MockLLM.generate] 模拟幻觉: {old_answer} -> {answer}")

        reasoning_steps = [
            "步骤1: 分析问题",
            f"步骤2: {reasoning}",
            f"步骤3: 得出答案 {answer}",
        ]
        return reasoning_steps, answer

    def validate(self, proposal: Dict) -> str:
        """
        Mock验证逻辑：模拟从幻觉、逻辑、意识形态角度验证

        关键修改：好节点会实际验证数学问题的答案是否正确
        """
        time.sleep(random.uniform(0.05, 0.2))

        answer = proposal.get("answer", "")
        reasoning = proposal.get("reasoning", [])
        task_content = proposal.get("task_content", "")  # 使用task_content而不是task_id

        # 基本验证规则
        if not answer or answer == "无":
            return "N"
        if not reasoning or len(reasoning) < 2:
            return "N"

        # 模拟验证：如果有明显错误则返回N
        if not answer.isdigit() and len(answer) > 20:  # 答案过长可能是幻觉
            return "N"

        # === 关键修改：好节点实际验证数学答案 ===
        # 尝试从task_content中提取数学问题并验证答案
        correct_answer = self._extract_and_validate_answer(task_content, answer)

        if not correct_answer:
            # 答案错误，返回N
            return "N"

        # 答案正确，返回Y
        return "Y"

    def _solve_math(self, question: str) -> Tuple[str, str]:
        """
        解析数学问题并计算答案

        支持两种格式：
        1. 纯数学表达式："2 + 2 = ?"
        2. 带system prompt的格式："你是一位数学专家...\n\n问题: 2 + 2 = ?"
        """
        try:
            # 提取数学表达式
            math_expr = None

            # 方法1：查找 "问题:" 或 "Question:" 后面的内容
            if "问题:" in question or "Question:" in question:
                # 分割字符串，取最后一部分（实际的问题）
                parts = question.split("问题:" if "问题:" in question else "Question:")
                if len(parts) > 1:
                    actual_question = parts[-1].strip()
                    # 提取等号前面的表达式
                    if "=" in actual_question:
                        expr = actual_question.split("=")[0].strip()
                        math_expr = expr

            # 方法2：如果没有标记，尝试直接从整个字符串中提取
            if math_expr is None and "=" in question:
                # 取最后一个等号前面的部分
                parts = question.rsplit("=", 1)
                if len(parts) > 1:
                    # 从这部分中提取数学表达式（找最后一个运算符后面的内容）
                    before_eq = parts[0].strip()
                    # 尝试从后往前找数字开始的位置
                    import re
                    # 匹配数学表达式（数字 运算符 数字）
                    match = re.search(r'(\d+(?:\.\d+)?\s*[+\-*/]\s*\d+(?:\.\d+)?)', before_eq)
                    if match:
                        math_expr = match.group(1)

            # 计算表达式
            if math_expr:
                result = eval(math_expr)
                return f"计算 {math_expr} = {result}", str(result)

        except Exception as e:
            print(f"[MockLLM._solve_math] 解析失败: {e}, question={repr(question)}")

        return "无法解析问题", "0"

    def _extract_and_validate_answer(self, task_id: str, proposed_answer: str) -> bool:
        """
        从task_id中提取数学问题并验证答案是否正确

        Args:
            task_id: 任务描述（可能包含数学问题）
            proposed_answer: leader提出的答案

        Returns:
            True if answer is correct, False otherwise
        """
        try:
            # 尝试从task_id中提取数学表达式（格式如 "2 + 2 = ?"）
            import re

            # 匹配数学表达式（支持 +, -, *, /）
            math_pattern = r'(\d+(?:\.\d+)?)\s*([+\-*/])\s*(\d+(?:\.\d+)?)'
            match = re.search(math_pattern, task_id)

            if match:
                # 提取操作数和运算符
                num1 = float(match.group(1))
                operator = match.group(2)
                num2 = float(match.group(3))

                # 计算正确答案
                if operator == '+':
                    correct_result = num1 + num2
                elif operator == '-':
                    correct_result = num1 - num2
                elif operator == '*':
                    correct_result = num1 * num2
                elif operator == '/':
                    correct_result = num1 / num2 if num2 != 0 else 0
                else:
                    return True  # 无法验证，默认通过

                # 比较答案（处理浮点数精度问题）
                try:
                    proposed_num = float(proposed_answer)
                    # 允许小的浮点数误差
                    is_correct = abs(proposed_num - correct_result) < 0.001

                    if not is_correct:
                        print(f"[验证] 答案错误: 预期 {correct_result}, 实际 {proposed_answer}")

                    return is_correct
                except ValueError:
                    # 无法转换为数字，答案格式错误
                    print(f"[验证] 答案格式错误: {proposed_answer}")
                    return False

            # 无法提取数学问题，默认通过
            return True

        except Exception as e:
            # 验证过程出错，保守策略：默认通过
            print(f"[验证] 验证过程出错: {e}")
            return True


class RealisticMockLLM(BaseLLM):
    """
    带有真实 LLM API 延迟分布的 Mock LLM

    使用对数正态分布 (log-normal) 模拟真实 LLM API 调用延迟，
    该分布是典型 API 响应时间的统计特征。

    延迟档位基于真实 LLM API 测量数据:
    - fast:   GLM-4-flash, DeepSeek-chat 等轻量模型
    - medium: GPT-3.5-turbo, Qwen-turbo 等标准模型
    - slow:   GPT-4, Qwen-max 等重度模型

    Args:
        accuracy: 答案准确率 (0.0-1.0)
        profile:  延迟档位 "fast" | "medium" | "slow"
    """

    # (generate_mean, generate_cv, validate_mean, validate_cv)
    # cv = coefficient of variation (变异系数)
    PROFILES = {
        "fast":   (0.8,  0.30, 0.4, 0.30),   # GLM-4-flash 级别
        "medium": (2.2,  0.35, 0.9, 0.30),   # GPT-3.5-turbo 级别
        "slow":   (4.5,  0.35, 1.8, 0.35),   # GPT-4 级别
    }

    def __init__(self, accuracy: float = 1.0, profile: str = "medium"):
        self.accuracy = accuracy
        p = self.PROFILES.get(profile, self.PROFILES["medium"])
        self.gen_mu, self.gen_cv, self.val_mu, self.val_cv = p
        # 复用 MockLLM 的数学求解逻辑
        self._solver = MockLLM(accuracy=1.0)

    def _realistic_delay(self, mu: float, cv: float) -> float:
        """
        使用对数正态分布生成真实感延迟

        Log-normal 分布特性:
        - 右偏: 大多数请求较快，少数请求较慢（符合 API 实际表现）
        - E[X] ≈ mu (均值约等于目标延迟)
        - 偶尔出现长尾延迟（模拟网络抖动/排队）
        """
        sigma = math.sqrt(math.log(1 + cv * cv))  # 对数正态的 sigma 参数
        mu_log = math.log(mu) - sigma * sigma / 2  # 对数正态的 mu 参数
        delay = random.lognormvariate(mu_log, sigma)
        # 截断: 最低 0.05s, 最高 5x 均值（模拟极端但不过分的延迟）
        return max(0.05, min(delay, mu * 5))

    def generate(self, question: str) -> Tuple[list, str]:
        # 模拟真实 LLM 生成延迟
        delay = self._realistic_delay(self.gen_mu, self.gen_cv)
        time.sleep(delay)

        # 复用 MockLLM 的数学求解（不走它的 sleep）
        reasoning, answer = self._solver._solve_math(question)

        # 按准确率随机引入错误
        if random.random() > self.accuracy:
            try:
                answer = str(int(float(answer)) + random.randint(1, 10))
            except ValueError:
                answer = str(random.randint(1, 100))

        steps = [
            "步骤1: 分析问题",
            f"步骤2: {reasoning}",
            f"步骤3: 得出答案 {answer}",
        ]
        return steps, answer

    def validate(self, proposal: Dict) -> str:
        # 模拟真实 LLM 验证延迟
        delay = self._realistic_delay(self.val_mu, self.val_cv)
        time.sleep(delay)

        # 复用 MockLLM 的验证逻辑
        return self._solver.validate(proposal)

    def health_check(self) -> bool:
        return True