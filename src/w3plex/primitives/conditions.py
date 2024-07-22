from typing import Optional

from ..core import Condition, ConditionConfig


class OnchainConditionsConfig(ConditionConfig):
    gas_price: Optional[float]
    block_number: Optional[int]


class OnchainConditions(Condition[OnchainConditionsConfig]):
    async def process(self):
        return super().process()