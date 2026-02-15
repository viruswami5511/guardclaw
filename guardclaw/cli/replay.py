"""
GuardClaw Phase 5: Replay CLI

Command-line interface for replay functionality.

Usage:
    guardclaw replay evidence-bundle/
    guardclaw replay evidence-bundle/ --json output.json
    guardclaw replay evidence-bundle/ --max-events 50
"""

import sys
import argparse
from pathlib import Path

from guardclaw.core.replay import ReplayEngine


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="GuardClaw Replay - Reconstruct evidence timeline"
    )
    
    parser.add_argument(
        "bundle",
        type=str,
        help="Path to evidence bundle directory"
    )
    
    parser.add_argument(
        "--json",
        type=str,
        help="Export replay to JSON file"
    )
    
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Maximum events to display (default: all)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Validate bundle path
    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        print(f"❌ Error: Bundle not found: {bundle_path}")
        sys.exit(1)
    
    try:
        # Create replay engine
        engine = ReplayEngine()
        
        # Load bundle
        if args.verbose:
            print(f"📂 Loading bundle: {bundle_path}")
        
        engine.load_bundle(bundle_path)
        
        # Reconstruct timeline
        if args.verbose:
            print("🔄 Reconstructing timeline...")
        
        engine.reconstruct_timeline()
        
        # Print timeline
        engine.print_timeline(max_events=args.max_events)
        
        # Export JSON if requested
        if args.json:
            engine.export_json(Path(args.json))
        
        sys.exit(0)
    
    except Exception as e:
        print(f"❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
