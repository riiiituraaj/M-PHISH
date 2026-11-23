"""Bound a Linux process tree, including resolver and optional renderer children."""

import os
import signal
import subprocess


def bounded_run(command, data, timeout):
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=os.name == "posix",
    )
    try:
        output, _ = process.communicate(data, timeout=timeout)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command)
        return output
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.communicate()
        raise
