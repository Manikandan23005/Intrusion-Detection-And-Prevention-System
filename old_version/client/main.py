import os
import sys
if '--debug' not in sys.argv:
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')
from monitor import IntrusionMonitor, AuthLogMonitor
import threading
import time
if __name__ == "__main__":
    
    print("Starting journalctl auth monitor...")
    auth_monitor_thread = threading.Thread(target=AuthLogMonitor().start, daemon=True)
    auth_monitor_thread.start()

    print("Starting file system monitor...")
    file_monitor = IntrusionMonitor(path="./")
    file_monitor_thread = threading.Thread(target=file_monitor.run, daemon=True)
    file_monitor_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nIDS stopped by user.")

