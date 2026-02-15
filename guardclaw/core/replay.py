"""
GuardClaw Phase 5: Replay Engine

Replay = Deterministic reconstruction of event sequence.

NOT:
- Full re-execution
- Time-travel debugging
- Simulation

IS:
- Timeline reconstruction
- Causal chain analysis
- Decision tracing
- Failure analysis

Design:
- Read-only (no state modification)
- Deterministic (same input = same output)
- Human-readable (timeline format)
- Machine-readable (JSON export)

The Trojan Horse:
Developers use GuardClaw for debugging, accidentally get accountability.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from collections import defaultdict

from guardclaw.core.observers import ObservationEvent, EventType
from guardclaw.core.emitter import SignedObservation
from guardclaw.core.genesis import GenesisRecord, AgentRegistration
from guardclaw.verification.verifier import ProofVerifier


@dataclass
class TimelineEvent:
    """
    Timeline event for replay.
    
    Enriched observation event with verification status.
    """
    timestamp: str
    event_type: str
    event_id: str
    subject_id: str
    action: str
    
    # Verification
    signature_valid: bool
    correlation_id: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Lag analysis
    accountability_lag_ms: Optional[float] = None
    
    def __lt__(self, other):
        """Sort by timestamp."""
        return self.timestamp < other.timestamp


@dataclass
class CausalChain:
    """
    Causal chain linking related events.
    
    Example:
    User Intent → Authorization → Execution → Settlement
    """
    chain_id: str
    events: List[TimelineEvent]
    complete: bool  # All expected events present
    
    def get_start_event(self) -> Optional[TimelineEvent]:
        """Get first event in chain."""
        return self.events[0] if self.events else None
    
    def get_end_event(self) -> Optional[TimelineEvent]:
        """Get last event in chain."""
        return self.events[-1] if self.events else None
    
    def duration_ms(self) -> Optional[float]:
        """Calculate chain duration."""
        if len(self.events) < 2:
            return None
        
        start = datetime.fromisoformat(self.events[0].timestamp.replace('Z', '+00:00'))
        end = datetime.fromisoformat(self.events[-1].timestamp.replace('Z', '+00:00'))
        
        return (end - start).total_seconds() * 1000


@dataclass
class ReplaySummary:
    """
    Summary of replay analysis.
    """
    total_events: int
    event_type_counts: Dict[str, int]
    
    # Verification
    valid_signatures: int
    invalid_signatures: int
    
    # Agents
    agents_seen: List[str]
    
    # Causal chains
    causal_chains: List[CausalChain]
    
    # Gaps
    heartbeat_gaps: List[Tuple[str, str]]  # (start, end) timestamps
    tombstones: List[TimelineEvent]
    
    # Lag analysis
    avg_lag_ms: Optional[float]
    max_lag_ms: Optional[float]
    p95_lag_ms: Optional[float]


class ReplayEngine:
    """
    Replay engine for timeline reconstruction.
    
    Capabilities:
    - Load evidence bundle
    - Reconstruct timeline
    - Analyze causal chains
    - Detect gaps
    - Calculate lag statistics
    - Export to JSON
    - Pretty-print timeline
    
    Usage:
        engine = ReplayEngine()
        engine.load_bundle("evidence-bundle/")
        timeline = engine.reconstruct_timeline()
        engine.print_timeline()
    """
    
    def __init__(self):
        self.genesis: Optional[GenesisRecord] = None
        self.agents: Dict[str, AgentRegistration] = {}
        self.observations: List[SignedObservation] = []
        self.timeline: List[TimelineEvent] = []
        self.causal_chains: List[CausalChain] = []
        self.verifier = ProofVerifier()
    
    def load_bundle(self, bundle_path: Path) -> None:
        """
        Load evidence bundle from directory.
        
        Expected structure:
        bundle/
        ├── genesis.json
        ├── agents/
        │   ├── agent-001.json
        │   └── agent-002.json
        └── observations/
            ├── intent.jsonl
            ├── execution.jsonl
            ├── result.jsonl
            ├── failure.jsonl
            ├── delegation.jsonl
            ├── heartbeat.jsonl
            └── tombstone.jsonl
        
        Args:
            bundle_path: Path to evidence bundle
        """
        bundle_path = Path(bundle_path)
        
        # Load genesis
        genesis_file = bundle_path / "genesis.json"
        if genesis_file.exists():
            with open(genesis_file) as f:
                self.genesis = GenesisRecord.from_dict(json.load(f))
        
        # Load agents
        agents_dir = bundle_path / "agents"
        if agents_dir.exists():
            for agent_file in agents_dir.glob("*.json"):
                with open(agent_file) as f:
                    agent = AgentRegistration.from_dict(json.load(f))
                    self.agents[agent.agent_id] = agent
        
        # Load observations
        obs_dir = bundle_path / "observations"
        if obs_dir.exists():
            for event_type in EventType:
                obs_file = obs_dir / f"{event_type.value}.jsonl"
                if obs_file.exists():
                    self._load_observations_file(obs_file)
        
        print(f"✅ Loaded bundle: {len(self.observations)} observations")
    
    def _load_observations_file(self, file_path: Path) -> None:
        """Load observations from JSONL file."""
        with open(file_path) as f:
            for line in f:
                if line.strip():
                    try:
                        obs_dict = json.loads(line)
                        obs = SignedObservation.from_dict(obs_dict)
                        self.observations.append(obs)
                    except Exception as e:
                        print(f"⚠️  Failed to load observation: {e}")
    
    def reconstruct_timeline(self) -> List[TimelineEvent]:
        """
        Reconstruct timeline from observations.
        
        Returns:
            Sorted list of timeline events
        """
        self.timeline = []
        
        for obs in self.observations:
            # Verify signature
            signature_valid = self._verify_signature(obs)
            
            # Create timeline event
            event = TimelineEvent(
                timestamp=obs.event.timestamp,
                event_type=obs.event.event_type.value,
                event_id=obs.event.event_id,
                subject_id=obs.event.subject_id,
                action=obs.event.action,
                signature_valid=signature_valid,
                correlation_id=obs.event.correlation_id,
                metadata=obs.event.metadata,
                accountability_lag_ms=obs.accountability_lag_ms
            )
            
            self.timeline.append(event)
        
        # Sort by timestamp
        self.timeline.sort()
        
        return self.timeline
    
    def _verify_signature(self, obs: SignedObservation) -> bool:
        """
        Verify observation signature.
        
        Args:
            obs: Signed observation
        
        Returns:
            True if signature valid, False otherwise
        """
        try:
            # Get agent key
            agent_id = obs.event.subject_id
            if agent_id not in self.agents:
                return False
            
            agent = self.agents[agent_id]
            
            # Verify signature
            from guardclaw.core.crypto import Ed25519KeyManager, canonical_json_encode
            
            public_key = Ed25519KeyManager.from_public_key_hex(agent.agent_public_key)
            event_dict = obs.event.to_dict()
            canonical_bytes = canonical_json_encode(event_dict)
            
            return public_key.verify(obs.signature, canonical_bytes)
        
        except Exception as e:
            print(f"⚠️  Signature verification failed: {e}")
            return False
    
    def build_causal_chains(self) -> List[CausalChain]:
        """
        Build causal chains from timeline.
        
        Chains are built by following correlation_id links.
        
        Returns:
            List of causal chains
        """
        self.causal_chains = []
        
        # Group by correlation_id
        chains: Dict[str, List[TimelineEvent]] = defaultdict(list)
        
        for event in self.timeline:
            if event.correlation_id:
                chains[event.correlation_id].append(event)
        
        # Create CausalChain objects
        for chain_id, events in chains.items():
            events.sort()  # Sort by timestamp
            
            chain = CausalChain(
                chain_id=chain_id,
                events=events,
                complete=self._is_chain_complete(events)
            )
            
            self.causal_chains.append(chain)
        
        return self.causal_chains
    
    def _is_chain_complete(self, events: List[TimelineEvent]) -> bool:
        """
        Check if causal chain is complete.
        
        Complete chain has:
        - Intent or Authorization
        - Execution
        - Result or Failure
        """
        event_types = {e.event_type for e in events}
        
        has_start = "intent" in event_types or "authorization" in event_types
        has_execution = "execution" in event_types
        has_end = "result" in event_types or "failure" in event_types
        
        return has_start and has_execution and has_end
    
    def detect_gaps(self) -> List[Tuple[str, str]]:
        """
        Detect gaps in heartbeat sequence.
        
        A gap is when no heartbeat received for > 2x interval.
        
        Returns:
            List of (start, end) timestamp tuples for gaps
        """
        gaps = []
        
        # Get all heartbeats
        heartbeats = [e for e in self.timeline if e.event_type == "heartbeat"]
        
        if len(heartbeats) < 2:
            return gaps
        
        # Expected interval (from first heartbeat metadata)
        # Assume 60 seconds if not specified
        expected_interval = 60
        
        for i in range(len(heartbeats) - 1):
            current = heartbeats[i]
            next_hb = heartbeats[i + 1]
            
            current_dt = datetime.fromisoformat(current.timestamp.replace('Z', '+00:00'))
            next_dt = datetime.fromisoformat(next_hb.timestamp.replace('Z', '+00:00'))
            
            gap_seconds = (next_dt - current_dt).total_seconds()
            
            # Gap if > 2x expected interval
            if gap_seconds > (expected_interval * 2):
                gaps.append((current.timestamp, next_hb.timestamp))
        
        return gaps
    
    def calculate_lag_statistics(self) -> Dict[str, float]:
        """
        Calculate accountability lag statistics.
        
        Returns:
            Dict with avg, max, p95 lag in milliseconds
        """
        lags = [
            e.accountability_lag_ms
            for e in self.timeline
            if e.accountability_lag_ms is not None
        ]
        
        if not lags:
            return {"avg": 0, "max": 0, "p95": 0}
        
        lags.sort()
        
        return {
            "avg": sum(lags) / len(lags),
            "max": max(lags),
            "p95": lags[int(len(lags) * 0.95)] if len(lags) > 0 else 0
        }
    
    def generate_summary(self) -> ReplaySummary:
        """
        Generate replay summary.
        
        Returns:
            ReplaySummary object
        """
        # Event type counts
        event_type_counts = defaultdict(int)
        for event in self.timeline:
            event_type_counts[event.event_type] += 1
        
        # Verification stats
        valid = sum(1 for e in self.timeline if e.signature_valid)
        invalid = len(self.timeline) - valid
        
        # Agents
        agents_seen = list({e.subject_id for e in self.timeline})
        
        # Causal chains
        self.build_causal_chains()
        
        # Gaps
        gaps = self.detect_gaps()
        tombstones = [e for e in self.timeline if e.event_type == "tombstone"]
        
        # Lag stats
        lag_stats = self.calculate_lag_statistics()
        
        return ReplaySummary(
            total_events=len(self.timeline),
            event_type_counts=dict(event_type_counts),
            valid_signatures=valid,
            invalid_signatures=invalid,
            agents_seen=agents_seen,
            causal_chains=self.causal_chains,
            heartbeat_gaps=gaps,
            tombstones=tombstones,
            avg_lag_ms=lag_stats.get("avg"),
            max_lag_ms=lag_stats.get("max"),
            p95_lag_ms=lag_stats.get("p95")
        )
    
    def print_timeline(self, max_events: Optional[int] = None) -> None:
        """
        Pretty-print timeline.
        
        Args:
            max_events: Max events to display (None = all)
        """
        if not self.timeline:
            print("⚠️  No timeline to display")
            return
        
        print("\n" + "="*80)
        print("📋 GuardClaw Replay")
        print("="*80)
        
        if self.genesis:
            print(f"Ledger: {self.genesis.ledger_name}")
            print(f"Created: {self.genesis.timestamp}")
        
        print(f"Events: {len(self.timeline)}")
        print(f"Agents: {len(self.agents)}")
        print("")
        
        # Timeline
        events_to_show = self.timeline[:max_events] if max_events else self.timeline
        
        for event in events_to_show:
            icon = self._get_event_icon(event.event_type)
            status = "✅" if event.signature_valid else "❌"
            
            # Timestamp (show time only)
            dt = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
            time_str = dt.strftime("%H:%M:%S.%f")[:-3]
            
            print(f"{time_str} │ {icon} {event.event_type.upper()}")
            print(f"         │ Subject: {event.subject_id}")
            print(f"         │ Action: {event.action}")
            
            if event.correlation_id:
                print(f"         │ Correlation: {event.correlation_id[:16]}...")
            
            if event.accountability_lag_ms:
                print(f"         │ Lag: {event.accountability_lag_ms:.1f}ms")
            
            print(f"         │ Signature: {status}")
            print("")
        
        if max_events and len(self.timeline) > max_events:
            print(f"... and {len(self.timeline) - max_events} more events")
            print("")
        
        # Summary
        summary = self.generate_summary()
        
        print("="*80)
        print("📊 Summary")
        print("="*80)
        print(f"Total events: {summary.total_events}")
        print(f"Valid signatures: {summary.valid_signatures}")
        print(f"Invalid signatures: {summary.invalid_signatures}")
        print(f"Causal chains: {len(summary.causal_chains)}")
        print(f"Heartbeat gaps: {len(summary.heartbeat_gaps)}")
        print(f"Tombstones: {len(summary.tombstones)}")
        
        if summary.avg_lag_ms:
            print(f"\nAccountability Lag:")
            print(f"  Average: {summary.avg_lag_ms:.1f}ms")
            print(f"  P95: {summary.p95_lag_ms:.1f}ms")
            print(f"  Max: {summary.max_lag_ms:.1f}ms")
        
        print("="*80 + "\n")
    
    def _get_event_icon(self, event_type: str) -> str:
        """Get icon for event type."""
        icons = {
            "intent": "💭",
            "execution": "⚡",
            "result": "✅",
            "failure": "❌",
            "delegation": "🔄",
            "heartbeat": "💓",
            "tombstone": "🪦"
        }
        return icons.get(event_type, "📝")
    
    def export_json(self, output_path: Path) -> None:
        """
        Export replay to JSON.
        
        Args:
            output_path: Output file path
        """
        summary = self.generate_summary()
        
        output = {
            "genesis": self.genesis.to_dict() if self.genesis else None,
            "agents": {aid: agent.to_dict() for aid, agent in self.agents.items()},
            "timeline": [
                {
                    "timestamp": e.timestamp,
                    "event_type": e.event_type,
                    "event_id": e.event_id,
                    "subject_id": e.subject_id,
                    "action": e.action,
                    "signature_valid": e.signature_valid,
                    "correlation_id": e.correlation_id,
                    "accountability_lag_ms": e.accountability_lag_ms
                }
                for e in self.timeline
            ],
            "causal_chains": [
                {
                    "chain_id": chain.chain_id,
                    "events": [e.event_id for e in chain.events],
                    "complete": chain.complete,
                    "duration_ms": chain.duration_ms()
                }
                for chain in summary.causal_chains
            ],
            "summary": {
                "total_events": summary.total_events,
                "event_type_counts": summary.event_type_counts,
                "valid_signatures": summary.valid_signatures,
                "invalid_signatures": summary.invalid_signatures,
                "agents_seen": summary.agents_seen,
                "heartbeat_gaps": summary.heartbeat_gaps,
                "avg_lag_ms": summary.avg_lag_ms,
                "max_lag_ms": summary.max_lag_ms,
                "p95_lag_ms": summary.p95_lag_ms
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"✅ Exported replay to {output_path}")
