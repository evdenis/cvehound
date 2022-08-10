#!/usr/bin/env python3

import os
import subprocess
from subprocess import PIPE


def get_active_cores():
    try:
        return len(os.sched_getaffinity(0))
    except Exception:
        # sched_getaffinity is not portable
        return os.cpu_count()


def get_threads_per_core():
    try:
        lscpu = subprocess.check_output(['lscpu'], stderr=PIPE, universal_newlines=True)
        line = next(line for line in lscpu.split('\n') if line.startswith('Thread(s)'))
        return int(line.split(':')[1])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return 1


def get_cocci_jobs():
    # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e16a7c47d56b4eeee82be662014c145bce2380e5
    # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c5864560d935db879cafa21feca0156d91eba842
    cores = get_active_cores()
    if get_threads_per_core() > 1 and cores > 4:
        cores = int(cores / 2)
    return cores
