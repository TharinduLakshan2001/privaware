import os
import hashlib
import time
import json
from datetime import datetime
import logging

class FileIntegrityMonitor:
    def __init__(self, filename="0045xr.c", check_interval=60, log_file="integrity_log.txt"):
        self.filename = filename
        self.check_interval = check_interval  # seconds
        self.log_file = log_file
        self.baseline_hash = None
        self.baseline_stats = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def calculate_file_hash(self, filename=None):
        """Calculate SHA-256 hash of the file"""
        if filename is None:
            filename = self.filename
            
        try:
            hash_sha256 = hashlib.sha256()
            with open(filename, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except FileNotFoundError:
            self.logger.error(f"File {filename} not found")
            return None
        except Exception as e:
            self.logger.error(f"Error calculating hash: {e}")
            return None
    
    def get_file_stats(self, filename=None):
        """Get file statistics (size, modification time, etc.)"""
        if filename is None:
            filename = self.filename
            
        try:
            stats = os.stat(filename)
            return {
                'size': stats.st_size,
                'modification_time': stats.st_mtime,
                'creation_time': stats.st_ctime if hasattr(stats, 'st_ctime') else None,
                'last_access': stats.st_atime
            }
        except FileNotFoundError:
            self.logger.error(f"File {filename} not found")
            return None
        except Exception as e:
            self.logger.error(f"Error getting file stats: {e}")
            return None
    
    def establish_baseline(self):
        """Establish baseline integrity measurements"""
        self.logger.info("Establishing baseline integrity measurements...")
        
        self.baseline_hash = self.calculate_file_hash()
        self.baseline_stats = self.get_file_stats()
        
        if self.baseline_hash and self.baseline_stats:
            baseline_data = {
                'filename': self.filename,
                'hash': self.baseline_hash,
                'stats': self.baseline_stats,
                'timestamp': datetime.now().isoformat()
            }
            
            # Save baseline to file
            with open(f"{self.filename}.baseline", "w") as f:
                json.dump(baseline_data, f, indent=2)
            
            self.logger.info("Baseline established successfully")
            self.logger.info(f"File hash: {self.baseline_hash}")
            self.logger.info(f"File size: {self.baseline_stats['size']} bytes")
            return True
        else:
            self.logger.error("Failed to establish baseline")
            return False
    
    def load_baseline(self):
        """Load baseline from file"""
        try:
            with open(f"{self.filename}.baseline", "r") as f:
                baseline_data = json.load(f)
            
            self.baseline_hash = baseline_data['hash']
            self.baseline_stats = baseline_data['stats']
            self.logger.info("Baseline loaded successfully")
            return True
        except FileNotFoundError:
            self.logger.warning("No baseline file found. Please establish baseline first.")
            return False
        except Exception as e:
            self.logger.error(f"Error loading baseline: {e}")
            return False
    
    def check_integrity(self):
        """Check current file integrity against baseline"""
        current_hash = self.calculate_file_hash()
        current_stats = self.get_file_stats()
        
        if not current_hash or not current_stats:
            return False, "File not accessible"
        
        issues = []
        
        # Check hash integrity
        if current_hash != self.baseline_hash:
            issues.append(f"Hash mismatch! Baseline: {self.baseline_hash}, Current: {current_hash}")
        
        # Check file size
        if current_stats['size'] != self.baseline_stats['size']:
            issues.append(f"Size changed! Baseline: {self.baseline_stats['size']} bytes, Current: {current_stats['size']} bytes")
        
        # Check modification time (optional - file might be legitimately modified)
        if current_stats['modification_time'] != self.baseline_stats['modification_time']:
            issues.append("File modification time changed")
        
        if issues:
            return False, "; ".join(issues)
        else:
            return True, "Integrity check passed"
    
    def monitor_continuously(self):
        """Continuous monitoring loop"""
        if not self.baseline_hash:
            if not self.load_baseline() and not self.establish_baseline():
                self.logger.error("Cannot start monitoring without baseline")
                return
        
        self.logger.info(f"Starting continuous monitoring of {self.filename}")
        self.logger.info(f"Check interval: {self.check_interval} seconds")
        self.logger.info("Press Ctrl+C to stop monitoring")
        
        try:
            while True:
                integrity_ok, message = self.check_integrity()
                
                if integrity_ok:
                    self.logger.info(f"Integrity check passed at {datetime.now()}")
                else:
                    self.logger.warning(f"INTEGRITY VIOLATION DETECTED: {message}")
                    # You can add additional actions here, like sending email alerts, etc.
                
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
    
    def single_check(self):
        """Perform a single integrity check"""
        if not self.baseline_hash:
            if not self.load_baseline():
                self.logger.error("No baseline available. Please establish baseline first.")
                return
        
        integrity_ok, message = self.check_integrity()
        
        if integrity_ok:
            self.logger.info(f"Integrity check PASSED: {message}")
        else:
            self.logger.error(f"Integrity check FAILED: {message}")
        
        return integrity_ok

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Monitor integrity of 0045xr.c file")
    parser.add_argument("--mode", choices=["single", "continuous"], default="continuous",
                       help="Monitoring mode (default: continuous)")
    parser.add_argument("--interval", type=int, default=60,
                       help="Check interval in seconds (default: 60)")
    parser.add_argument("--file", default="0045xr.c",
                       help="File to monitor (default: 0045xr.c)")
    parser.add_argument("--establish-baseline", action="store_true",
                       help="Establish new baseline before monitoring")
    
    args = parser.parse_args()
    
    # Create monitor instance
    monitor = FileIntegrityMonitor(
        filename=args.file,
        check_interval=args.interval
    )
    
    # Establish baseline if requested
    if args.establish_baseline:
        if not monitor.establish_baseline():
            return
    
    # Run monitoring
    if args.mode == "single":
        monitor.single_check()
    else:
        monitor.monitor_continuously()

if __name__ == "__main__":
    main()
