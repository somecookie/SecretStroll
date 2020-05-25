import pathlib
import os
import subprocess
import time
import argparse
import shutil


def capture(host,iteration):
    capture_path = "captures"
    capture_file = pathlib.Path(capture_path)
    if capture_file.exists():
        raise RuntimeError("Remove the directory captures before running this script")
    
    os.mkdir(capture_path)

    for cell_id in range(1, 101):
        cell_path = f"{capture_file}/cell_{cell_id}"
        os.mkdir(cell_path)    
        for i in range(iteration):
            cmd = f"tcpdump host {host} -i any -w {cell_path}/run{i}.pcap".split(" ")
            print(cmd)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            os.system(f"python3 client.py grid -p key-client.pub -c attr.cred -r '' -t {cell_id}")
            time.sleep(1)
            p.send_signal(subprocess.signal.SIGTERM)
            time.sleep(1)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="Address IP of the client", type=str, default="172.18.0.2")
    parser.add_argument("--it", help="Number of iteration per cell", type=int, default=150)
    return parser.parse_args()

# domains = ["www.google.com"]
# for domain in domains:
#     print("="*10,"Query to", domain,"="*10)
    
#     cmd = f"tcpdump host 192.168.1.20 -i any -w {domain}.pcap".split(" ")
#     print(cmd)
#     p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
#     os.system(f"curl {domain}")
#     time.sleep(1)
#     p.send_signal(subprocess.signal.SIGTERM)
#     time.sleep(1)

if __name__ == "__main__":
    """
    For this script to work follow the same steps as in the README `A sample run of Part 3` replacing the last command of the client by:
    `python3 capture.py --ip <IP of the client> --it <number of iterations> `
    """
    args = get_args()
    print(args)
    capture(args.ip, args.it)