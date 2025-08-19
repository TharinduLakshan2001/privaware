#!/usr/bin/env python3
import subprocess
import sys

def call_with_linphone(number):
    """Call using linphone (install: sudo apt install linphone)"""
    try:
        subprocess.run(["linphonec", "sh", "exit", f"call {number}"], 
                      timeout=30, check=True)
        return True
    except Exception as e:
        print(f"Linphone error: {e}")
        return False

def call_with_modem(number):
    """Call using modem tools (advanced, requires modem setup)"""
    try:
        # This is very system-dependent
        subprocess.run(["echo", f"ATD{number};", ">/dev/ttyACM0"], check=True)
        return True
    except Exception as e:
        print(f"Modem error: {e}")
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python call.py <phone_number>")
        print("Example: python call.py +94123456789")
        sys.exit(1)
    
    number = sys.argv[1]
    print(f"Attempting to call {number}...")
    
    # Try different methods
    if call_with_linphone(number):
        print("Call initiated with Linphone")
    elif call_with_modem(number):
        print("Call initiated with modem")
    else:
        print("No calling methods available")

if __name__ == "__main__":
    main()
