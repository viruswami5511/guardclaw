"""
GuardClaw CLI - Main Entry Point
"""

import sys
from pathlib import Path


def main():
    """Main CLI entry point."""

    if len(sys.argv) < 2:
        print_usage()
        return

    command = sys.argv[1]

    if command == "replay":
        replay_command()
    elif command == "version":
        version_command()
    elif command in ("help", "--help", "-h"):
        print_usage()
    else:
        print(f"Unknown command: {command}")
        print()
        print_usage()
        sys.exit(1)


def print_usage():
    """Print CLI usage."""
    print("GuardClaw CLI v0.1.2")
    print()
    print("Usage:")
    print("  guardclaw replay <ledger-path>   Verify evidence ledger")
    print("  guardclaw version                Show version")
    print("  guardclaw help                   Show this help")
    print()
    print("Example:")
    print("  guardclaw replay .guardclaw/ledger")


def version_command():
    """Show version."""
    print("GuardClaw v0.1.2")
    print("Cryptographic evidence ledger for autonomous agent accountability")


def replay_command():
    """Replay evidence from ledger."""
    if len(sys.argv) < 3:
        print("❌ Error: ledger path required")
        print()
        print("Usage:")
        print("  guardclaw replay <ledger-path>")
        print()
        print("Example:")
        print("  guardclaw replay .guardclaw/ledger")
        sys.exit(1)
    
    ledger_path = Path(sys.argv[2])
    
    if not ledger_path.exists():
        print(f"❌ Error: Ledger not found: {ledger_path}")
        sys.exit(1)
    
    # Import here to avoid circular imports
    from guardclaw.core.emitter import SignedObservation
    from guardclaw.core.crypto import Ed25519KeyManager, canonical_json_encode
    from cryptography.hazmat.primitives import serialization
    import json
    
    print()
    print("="*60)
    print("GuardClaw Replay")
    print("="*60)
    print(f"Ledger: {ledger_path}")
    print()
    
    try:
        # Load observations
        obs_dir = ledger_path / "observations"
        if not obs_dir.exists():
            print(f"❌ Error: No observations found in {ledger_path}")
            sys.exit(1)
        
        # Load keys
        keys_dir = ledger_path.parent / "keys"
        agent_keys = {}
        agent_key_versions = {}
        
        if keys_dir.exists():
            # Load ephemeral agent public key
            agent_pub_key_file = keys_dir / "ephemeral_agent.pub"
            if agent_pub_key_file.exists():
                try:
                    with open(agent_pub_key_file, 'rb') as f:
                        public_key_pem = f.read()
                        public_key = serialization.load_pem_public_key(public_key_pem)
                        
                        public_bytes = public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                        public_key_hex = public_bytes.hex()
                        
                        # Store for multiple agent IDs
                        agent_keys["test-agent-001"] = public_key_hex
                        agent_keys["ghost-agent"] = public_key_hex
                        agent_keys["gap-agent"] = public_key_hex
                        
                        print(f"🔑 Loaded ephemeral agent key")
                except Exception as e:
                    print(f"⚠️  Failed to load agent key: {e}")
        
        # Load from agents/ directory
        agents_dir = ledger_path.parent / "agents"
        if agents_dir.exists():
            for agent_file in agents_dir.glob("*.json"):
                try:
                    with open(agent_file) as f:
                        agent_data = json.load(f)
                        agent_id = agent_data.get("agent_id")
                        public_key = agent_data.get("agent_public_key")
                        
                        if agent_id and public_key:
                            if agent_id not in agent_key_versions:
                                agent_key_versions[agent_id] = []
                            
                            agent_key_versions[agent_id].append(public_key)
                            agent_keys[agent_id] = public_key
                            
                            version = "v" + str(len(agent_key_versions[agent_id]))
                            print(f"🔑 Loaded key for {agent_id} ({version})")
                except Exception:
                    pass
        
        # Load all observations from JSONL files
        observations = []
        for jsonl_file in obs_dir.glob("*.jsonl"):
            with open(jsonl_file) as f:
                for line in f:
                    if line.strip():
                        try:
                            obs_dict = json.loads(line)
                            obs = SignedObservation.from_dict(obs_dict)
                            observations.append(obs)
                        except Exception as e:
                            print(f"⚠️  Failed to parse observation: {e}")
        
        if not observations:
            print("⚠️  No observations found")
            sys.exit(0)
        
        print(f"📊 Loaded {len(observations)} observations")
        
        can_verify = len(agent_keys) > 0 or len(agent_key_versions) > 0
        if not can_verify:
            print("⚠️  No keys found - signature verification will be skipped")
        
        print()
        
        # Sort by timestamp
        observations.sort(key=lambda o: o.event.timestamp)
        
        # Verify signatures and check for replays
        tampering_detected = False
        replay_detected = False
        valid_count = 0
        invalid_count = 0
        unverified_count = 0
        
        # Per-agent replay detection (GPT's correction)
        seen_nonces = {}  # {subject_id: set(nonces)}
        
        for obs in observations:
            subject_id = obs.event.subject_id
            
            # Check for replay attack (per-agent)
            if hasattr(obs.event, 'nonce') and obs.event.nonce is not None:
                # Initialize set for this agent if needed
                if subject_id not in seen_nonces:
                    seen_nonces[subject_id] = set()
                
                # Check for replay
                if obs.event.nonce in seen_nonces[subject_id]:
                    obs.is_replay = True
                    replay_detected = True
                else:
                    seen_nonces[subject_id].add(obs.event.nonce)
                    obs.is_replay = False
            else:
                # Old event without nonce - can't check replay
                obs.is_replay = None
            
            # Signature verification
            matched_keys = []
            
            if subject_id in agent_key_versions:
                matched_keys = agent_key_versions[subject_id]
            elif subject_id in agent_keys:
                matched_keys = [agent_keys[subject_id]]
            elif subject_id.startswith("observer-"):
                matched_keys = list(agent_keys.values())
            
            if can_verify and matched_keys:
                is_valid = False
                for key_hex in matched_keys:
                    try:
                        key_manager = Ed25519KeyManager.from_public_key_hex(key_hex)
                        
                        # Get event dict for verification
                        event_dict = obs.event.to_dict()
                        
                        # SAFE: If nonce is None, it won't be in dict
                        # (from_dict sets it to None for old events)
                        canonical_bytes = canonical_json_encode(event_dict)
                        
                        # Verify
                        if key_manager.verify(obs.signature, canonical_bytes):
                            is_valid = True
                            break
                    except Exception:
                        continue
                
                if is_valid:
                    valid_count += 1
                else:
                    invalid_count += 1
                    tampering_detected = True
                
                obs.signature_valid = is_valid
            else:
                obs.signature_valid = None
                unverified_count += 1
        
        # Display timeline
        print("="*60)
        print("Timeline")
        print("="*60)
        print()
        
        for obs in observations:
            event = obs.event
            
            # Event icon
            icons = {
                "intent": "💭",
                "execution": "⚡",
                "result": "✅",
                "failure": "❌",
                "delegation": "🔄",
                "heartbeat": "💓"
            }
            icon = icons.get(event.event_type.value, "📝")
            
            # Check for replay
            if hasattr(obs, 'is_replay') and obs.is_replay:
                icon = "🚨"
            
            # Timestamp
            from datetime import datetime
            try:
                dt = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime("%H:%M:%S.%f")[:-3]
            except:
                time_str = event.timestamp[:8]
            
            # Signature status
            if obs.signature_valid is None:
                sig_status = "⚠️  UNVERIFIED"
            elif obs.signature_valid:
                sig_status = "✅ VALID"
            else:
                sig_status = "❌ INVALID (TAMPERED)"
                icon = "⚠️"
            
            print(f"{time_str} │ {icon} {event.event_type.value.upper()}")
            print(f"         │ Subject: {event.subject_id}")
            print(f"         │ Action: {event.action}")
            
            if event.correlation_id:
                print(f"         │ Correlation: {event.correlation_id[:16]}...")
            
            if hasattr(obs, 'accountability_lag_ms') and obs.accountability_lag_ms:
                print(f"         │ Lag: {obs.accountability_lag_ms:.1f}ms")
            
            print(f"         │ Signature: {sig_status}")
            
            if not obs.signature_valid and obs.signature_valid is not None:
                print(f"         │ 🚨 WARNING: Event has been modified after signing!")
            
            if hasattr(obs, 'is_replay') and obs.is_replay:
                nonce_preview = event.nonce[:8] if event.nonce else "unknown"
                print(f"         │ 🚨 REPLAY ATTACK: Nonce {nonce_preview}... seen before for this agent!")
            
            print()
        
        # Summary
        print("="*60)
        print("Summary")
        print("="*60)
        print(f"Total events: {len(observations)}")
        
        from collections import Counter
        event_types = Counter(obs.event.event_type.value for obs in observations)
        for event_type, count in event_types.items():
            print(f"  {event_type}: {count}")
        
        print()
        print("Signature Verification:")
        if can_verify:
            print(f"  ✅ Valid: {valid_count}")
            print(f"  ❌ Invalid (tampered): {invalid_count}")
            print(f"  ⚠️  Unverified (no key): {unverified_count}")
            
            if tampering_detected:
                print()
                print("🚨 TAMPERING DETECTED")
                print("   One or more events have been modified after signing.")
                print("   This ledger is COMPROMISED.")
            
            if replay_detected:
                print()
                print("🚨 REPLAY ATTACK DETECTED")
                print("   One or more events have duplicate nonces within the same agent.")
                print("   Events may have been replayed from a captured session.")
        else:
            print(f"  ⚠️  Verification skipped (no keys available)")
        
        print("="*60)
        print()
        
        if tampering_detected or replay_detected:
            if tampering_detected and replay_detected:
                print("❌ Replay complete - TAMPERING AND REPLAY ATTACKS DETECTED")
            elif tampering_detected:
                print("❌ Replay complete - TAMPERING DETECTED")
            else:
                print("❌ Replay complete - REPLAY ATTACK DETECTED")
            sys.exit(1)
        else:
            print("✅ Replay complete")
        
    except Exception as e:
        print(f"❌ Error during replay: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
