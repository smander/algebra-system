"""Helpers for sampling rate specifications like 1/100."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class Sampler:
    numerator: int
    denominator: int
    _counter: int = 0

    def allow(self) -> bool:
        if self.denominator <= 0:
            return True
        self._counter += 1
        if self._counter >= self.denominator:
            self._counter = 0
            return True
        return False


class SamplerFactory:
    @staticmethod
    def from_spec(spec: Optional[str]) -> Optional[Sampler]:
        if not spec:
            return None
        try:
            num, den = SamplerFactory._parse_fraction(spec)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid sampling spec '{spec}'") from exc
        return Sampler(num, den)

    @staticmethod
    def _parse_fraction(spec: str) -> Tuple[int, int]:
        if "/" not in spec:
            value = int(spec)
            return value, 1
        left, right = spec.split("/", 1)
        return int(left), int(right)
