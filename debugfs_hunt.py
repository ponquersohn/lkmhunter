import os
from pathlib import Path
import subprocess
import logging
import sys


def initialize_debugfs(device):

    process = subprocess.Popen(
        ["sudo", "debugfs", device],
        bufsize=1,
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
    )
    return process


def run_debugfs(process: subprocess.Popen, command):
    # mystd_in, process = debugfs
    process.stdin.write(command + "\n")
    output = []
    while True:
        line = process.stdout.readline()
        if line == "\n":
            break
        if line.startswith("debugfs: No such file or directory while"):
            raise Exception(f"Cant continue: {line}")
        if line == "debugfs:  " + command + "\n":
            continue
        if line.startswith("debugfs"):
            logging.debug(f"Skipping {line}")
            continue
        if line == "Usage: ls [-c] [-d] [-l] [-p] [-r] file\n":
            logging.warning(f"Unable to handle command: {command}")
            break
        output.append(line)
    return output[1:]


def parse_entry(entry):
    t = entry.split("/")
    ret = {"type": t[2][:-4], "perm": t[2], "name": t[5]}
    return ret


def ls_dir(debugfs, dir):
    logging.debug(f"Working on: {dir}")
    output = run_debugfs(debugfs, f"ls -lp {dir}")
    for entry in output:
        parsed_entry = parse_entry(entry)
        if parsed_entry["name"] in [".", ".."]:
            continue
        # print(parsed_entry)
        if parsed_entry["type"] == "04":
            # its dir
            for file in ls_dir(debugfs, dir + "/" + parsed_entry["name"]):
                yield file
        if parsed_entry["type"] == "10":
            yield dir + "/" + parsed_entry["name"]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # with temp_fifo() as stdin:

    if len(sys.argv) == 3:
        device = sys.argv[1]
        mountpoint = sys.argv[2]
    else:
        device = "/dev/system/root"
        mountpoint = "/mnt"
    mountpoint = Path(mountpoint)
    logging.info(f"Comparing device: {device} with mount: {mountpoint}")
    debugfs = initialize_debugfs("/dev/system/root")
    ret = list(ls_dir(debugfs, ""))
    # print("\n".join(ret))
    all_folders = {}
    for file in [Path(x) for x in ret]:
        mounted_file = mountpoint / file.relative_to(file.anchor)
        # if not mounted_file.is_file():
        #   print(f"Missing file: {file} under {mountpoint}")
        parent = mounted_file.parent
        contents = all_folders.get(str(parent), os.listdir(str(parent)))
        all_folders[str(parent)] = contents
        if not file.name in contents:
            print(f"Missing file: {file} under {mountpoint}")
    print("all done")
