"""Atomic publication and rollback for validated policy bundles."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from .bundle import PolicyBundle
from .policy import PolicyEngine


class PolicyUpdateConflict(RuntimeError):
    """Raised when a compare-and-swap policy update uses a stale generation."""


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """Immutable, internally consistent view of one policy generation."""

    generation: int
    bundle: PolicyBundle
    engine: PolicyEngine

    @property
    def policy_id(self) -> str:
        return self.bundle.policy_id

    @property
    def version(self) -> str:
        return self.bundle.version

    @property
    def digest(self) -> str:
        return self.bundle.digest


class PolicyRegistry:
    """Thread-safe registry that swaps complete validated policy snapshots atomically.

    Load and validate candidate files before publication. Readers receive one
    immutable snapshot, so a decision and its matched rule definitions can be
    evaluated against the same generation. Optional expected-generation checks
    prevent stale deployers from overwriting a newer policy. Rollback publishes
    a previous bundle as a new generation rather than rewinding generation IDs.
    """

    def __init__(self, initial: PolicyBundle, *, history_limit: int = 10) -> None:
        if not isinstance(initial, PolicyBundle):
            raise TypeError("initial must be a PolicyBundle instance")
        if isinstance(history_limit, bool) or not isinstance(history_limit, int):
            raise ValueError("history_limit must be a positive integer")
        if history_limit < 1:
            raise ValueError("history_limit must be a positive integer")
        self._lock = RLock()
        self._history_limit = history_limit
        self._history: list[PolicySnapshot] = []
        self._current = self._make_snapshot(initial, generation=1)

    @staticmethod
    def _make_snapshot(bundle: PolicyBundle, *, generation: int) -> PolicySnapshot:
        return PolicySnapshot(generation=generation, bundle=bundle, engine=bundle.engine)

    def snapshot(self) -> PolicySnapshot:
        """Return a stable reference to the currently published policy snapshot."""

        with self._lock:
            return self._current

    @property
    def history(self) -> tuple[PolicySnapshot, ...]:
        """Return retained prior snapshots, oldest first."""

        with self._lock:
            return tuple(self._history)

    def publish(
        self,
        candidate: PolicyBundle,
        *,
        expected_generation: int | None = None,
    ) -> PolicySnapshot:
        """Atomically publish a validated candidate, optionally using compare-and-swap."""

        if not isinstance(candidate, PolicyBundle):
            raise TypeError("candidate must be a PolicyBundle instance")
        if expected_generation is not None and (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation < 1
        ):
            raise ValueError("expected_generation must be a positive integer or None")

        # Construct the whole candidate before acquiring the publication lock.
        # Readers never observe a half-built snapshot.
        candidate_snapshot = self._make_snapshot(candidate, generation=0)
        with self._lock:
            current = self._current
            if (
                expected_generation is not None
                and expected_generation != current.generation
            ):
                raise PolicyUpdateConflict(
                    f"expected policy generation {expected_generation}, "
                    f"found {current.generation}"
                )
            if candidate.policy_id != current.policy_id:
                raise ValueError("candidate policy_id must match the registry policy_id")

            known_snapshots = (*self._history, current)
            for known in known_snapshots:
                if (
                    known.bundle.version == candidate.version
                    and known.bundle.digest != candidate.digest
                ):
                    raise ValueError(
                        "a published policy version cannot be reused with different content"
                    )

            if candidate.digest == current.digest and candidate.version == current.version:
                return current

            self._history.append(current)
            if len(self._history) > self._history_limit:
                del self._history[: len(self._history) - self._history_limit]
            self._current = PolicySnapshot(
                generation=current.generation + 1,
                bundle=candidate_snapshot.bundle,
                engine=candidate_snapshot.engine,
            )
            return self._current

    def reload(
        self,
        path: str | Path,
        *,
        expected_generation: int | None = None,
    ) -> PolicySnapshot:
        """Load and validate a policy file, then atomically publish it."""

        candidate = PolicyBundle.from_file(path)
        return self.publish(candidate, expected_generation=expected_generation)

    def rollback(self, *, expected_generation: int | None = None) -> PolicySnapshot:
        """Publish the most recent retained snapshot as a new generation."""

        if expected_generation is not None and (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation < 1
        ):
            raise ValueError("expected_generation must be a positive integer or None")

        with self._lock:
            current = self._current
            if (
                expected_generation is not None
                and expected_generation != current.generation
            ):
                raise PolicyUpdateConflict(
                    f"expected policy generation {expected_generation}, "
                    f"found {current.generation}"
                )
            if not self._history:
                raise RuntimeError("no previous policy snapshot is available for rollback")

            previous = self._history.pop()
            self._current = PolicySnapshot(
                generation=current.generation + 1,
                bundle=previous.bundle,
                engine=previous.engine,
            )
            return self._current
