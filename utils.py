import collections
import re
import subprocess

from kernel import KprocSegment


def get_running_kernel():
    result = subprocess.run(["uname", "-r"], stdout=subprocess.PIPE)
    return result.stdout.decode("utf-8").strip()
