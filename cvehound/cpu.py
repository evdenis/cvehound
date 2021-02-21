#!/usr/bin/env python3

import os
import subprocess
from subprocess import PIPE

def get_active_cores():
    return len(os.sched_getaffinity(0))

def get_threads_per_core():
    lscpu = (subprocess.run(['lscpu'],
                stdout=PIPE, stderr=PIPE, check=True)
            .stdout.decode('utf-8'))
    line = next(line for line in lscpu.split('\n') if line.startswith('Thread(s)'))
    return int(line.split(':')[1])


class CPU():

    def __init__(self):
        self.cores = os.cpu_count()
        self.active_cores = get_active_cores()
        self.threads_per_core = get_threads_per_core()

    def get_cores(self):
        return self.cores

    def get_active_cores(self):
        return get_active_cores()

    def get_threads_per_core(self):
        return self.threads_per_core

    def get_cocci_jobs(self):
        # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e16a7c47d56b4eeee82be662014c145bce2380e5
        # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c5864560d935db879cafa21feca0156d91eba842
        cores = self.get_active_cores()
        if self.threads_per_core > 1 and cores > 4:
            cores = int(cores / 2)
        return cores
