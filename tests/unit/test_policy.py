from app.config.settings import PolicySettings
from app.detectors.base import Detection
from app.policy.engine import PolicyEngine


def test_policy_uses_strictest_action() -> None:
    engine = PolicyEngine(
        PolicySettings(
            default_action="allow",
            rules={
                "email": "mask",
                "openai_key": "block",
            },
        )
    )

    decision = engine.decide(
        [
            Detection(type="email", start=0, end=1, detector="test"),
            Detection(type="openai_key", start=2, end=3, detector="test"),
        ]
    )

    assert decision.final_action == "block"
    assert decision.blocked is True
    assert decision.actions == ["mask", "block"]
