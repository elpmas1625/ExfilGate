from dataclasses import dataclass
from typing import Literal

from app.detectors.base import Detection

Action = Literal["allow", "warn", "mask", "block"]


@dataclass(frozen=True)
class PolicyDecision:
    detections: list[Detection]
    actions: list[Action]
    final_action: Action

    @property
    def blocked(self) -> bool:
        return self.final_action == "block"

    @property
    def should_mask(self) -> bool:
        return self.final_action == "mask"
