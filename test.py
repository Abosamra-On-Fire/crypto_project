import subprocess
import time
import sys
from pathlib import Path

def run_test():

    receiver_proc = subprocess.Popen(
        [sys.executable, "reciever.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    print("ran receiver.py (waiting 2 sec for initialization)...")
    time.sleep(2)

    print("running sender.py...")
    sender_result = subprocess.run(
        [sys.executable, "sender.py"],
        capture_output=True,
        text=True
    )
    
    print("\n=== SENDER OUTPUT ===")
    print(sender_result.stdout)
    if sender_result.stderr:
        print("!!! SENDER ERRORS !!!")
        print(sender_result.stderr)

    receiver_proc.terminate()
    receiver_out, receiver_err = receiver_proc.communicate()
    
    print("\n=== RECEIVER OUTPUT ===")
    print(receiver_out.decode())
    if receiver_err:
        print("!!! RECEIVER ERRORS !!!")
        print(receiver_err.decode())

    print("\n=== VERIFICATION ===")
    try:
        with open("input.txt", "rb") as f:
            original = f.read()
        with open("output.txt", "rb") as f:
            decrypted = f.read()
        
        if original == decrypted:
            print("SUCCESS: output.txt matches input.txt exactly")
            print(f"File size: {len(original)} bytes verified")
        else:
            print("FAILURE: Files differ!")
    except FileNotFoundError:
        print("ERROR: output.txt not created")

if __name__ == "__main__":
    run_test()