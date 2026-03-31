from typing import List, Dict, Any
import random

def select_top_k_attack_strategies(round_data: List[dict], top_k: int) -> List[str]:
    """
    Select the top k attack strategies based on the round data.
    
    Args:
        round_data: List of dictionaries containing the round data.
        top_k: Number of top attack strategies to select.
    
    Returns:
        List of top k attack strategies.
    """
    pass


def select_next_attack_strategy(strategy_ranking: Dict[str, Dict[str, Any]], attack_type: str) -> str:
    """
    Select the next attack strategy based on the strategy ranking.
    
    Args:
        strategy_ranking: Dictionary containing the strategy ranking.
    
    Returns:
        Next attack strategy.
    """

    strategies = strategy_ranking[attack_type]
    idx = random.randint(0, len(strategies) - 1)
    return strategies[idx]
