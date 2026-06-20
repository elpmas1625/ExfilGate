from app.config.settings import PolicySettings
from app.detectors.base import Detection
from app.policy.models import Action, PolicyDecision

ACTION_RANK: dict[Action, int] = {
    "allow": 0,
    "warn": 1,
    "mask": 2,
    "block": 3,
}


class PolicyEngine:
    def __init__(self, settings: PolicySettings) -> None:
        self.settings = settings

    def decide(self, detections: list[Detection]) -> PolicyDecision:
        actions: list[Action] = []
        for detection in detections:
            actions.append(self.settings.rules.get(detection.type, self.settings.default_action))

        if not actions:
            return PolicyDecision(detections=detections, actions=["allow"], final_action="allow")

        final_action = max(actions, key=lambda action: ACTION_RANK[action])
        return PolicyDecision(detections=detections, actions=sorted(set(actions), key=lambda action: ACTION_RANK[action]), final_action=final_action)
