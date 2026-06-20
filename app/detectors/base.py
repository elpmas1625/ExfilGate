from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Detection:
    type: str
    start: int
    end: int
    detector: str


class Detector(Protocol):
    name: str

    def detect(self, text: str) -> list[Detection]:
        ...
