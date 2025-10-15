# Add these functions to config_checker.py or create a new snapshots.py
def list_snapshots(snapshot_dir="~/.privaware/snapshots"):
    """List all snapshots"""
    snapshot_path = Path(os.path.expanduser(snapshot_dir))
    snapshots = list(snapshot_path.glob("snapshot_*.json"))
    snapshots.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    
    print("📸 Available Snapshots:")
    print("=" * 50)
    for snapshot in snapshots:
        timestamp = snapshot.stem.replace("snapshot_", "")
        size = snapshot.stat().st_size
        print(f"  {timestamp} ({size} bytes)")

def show_snapshot(snapshot_file, snapshot_dir="~/.privaware/snapshots"):
    """Show snapshot details"""
    snapshot_path = Path(os.path.expanduser(snapshot_dir)) / snapshot_file
    if not snapshot_path.exists():
        print(f"❌ Snapshot {snapshot_file} not found")
        return
    
    with open(snapshot_path, 'r') as f:
        data = json.load(f)
    
    print(f"📊 Snapshot: {snapshot_file}")
    print(f"⏰ Timestamp: {data.get('timestamp', 'Unknown')}")
    print(f"🔐 Signature: {data.get('signature', 'None')[:16]}...")
    print("\n📋 Check Results:")
    print("-" * 30)
    
    for check in data.get('checks', []):
        status_icon = {
            "PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "UNKNOWN": "❓"
        }.get(check.get('status', 'UNKNOWN'), "❓")
        
        print(f"{status_icon} {check.get('check_id', 'Unknown'):20} [{check.get('status', 'UNKNOWN'):6}]")
        if check.get('details'):
            print(f"   {check.get('details')}")
