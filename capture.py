import pathlib
import os
import subprocess
import time
import argparse
import shutil

capture_path = "captures"

def capture(host,iteration):
    capture_file = pathlib.Path(capture_path)
    if capture_file.exists():
        raise RuntimeError("Remove the directory captures before running this script")
    
    os.mkdir(capture_path)

    for cell_id in range(1, 101):
        cell_path = f"{capture_file}/cell_{cell_id}"
        os.mkdir(cell_path)    
        for i in range(iteration):
            cmd = f"tcpdump host {host} -i any -w {cell_path}/run{i}.pcap".split(" ")
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            os.system(f"python3 client.py grid -p key-client.pub -c attr.cred -r '' -t {cell_id}")
            p.send_signal(subprocess.signal.SIGTERM)

def convert():
    capture_file = pathlib.Path(capture_path)
    if not capture_file.exists():
        raise RuntimeError("Please start a capture first.")

    for run_path in capture_file.glob("*/*.pcap"):
        new_path = run_path.with_suffix('.csv')
        cmd = "tshark -r {} -T fields -e _ws.col.Time -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e _ws.col.Length -e _ws.col.Info -E header=y -E separator=, -E quote=d > {}".format(run_path, new_path)
        err = os.system(cmd)
        if err != 0:
            print("Error with file {}.".format(new_path))
        else:
            run_path.unlink()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="Address IP of the client", type=str, default="172.18.0.2")
    parser.add_argument("--it", help="Number of iteration per cell", type=int, default=150)
    parser.add_argument("--convert", help="In place conversion of the captures in /captures to csv files", action='store_true')
    return parser.parse_args()

if __name__ == "__main__":
    """
    For this script to work follow the same steps as in the README `A sample run of Part 3` replacing the last command of the client by:
    `python3 capture.py --ip <IP of the client> --it <number of iterations> `
    """
    args = get_args()
    if args.convert:
        convert()
    else:
        capture(args.ip, args.it)
