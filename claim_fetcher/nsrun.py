"""Starting the worker inside a fresh unprivileged user + network namespace.

`unshare --user --net --map-root-user` needs no capability: the kernel lets an unprivileged process create a user
namespace (max_user_namespaces > 0, and a seccomp profile that allows unshare/clone with CLONE_NEWUSER, which the
witness-dev pods have: their seccomp is Unconfined) and, as root of that user namespace, a network namespace owned by
it. util-linux `unshare` execs the worker directly, so the worker and Chromium share one process group that is killed
as a whole at the deadline.

The worker gets a minimal environment: never the service's secret path or any other variable that is not listed here.
It also gets its own mount namespace (`--mount --propagation unchanged`), in which it covers the service's secret
directory and the service-account token directory with an empty read-only tmpfs before Chromium starts
(sandbox.hide_paths): the worker runs under the service's own uid, so without this a browser escape could read them.
`unchanged`, because some hosts refuse the remount that `private` needs; it is still one-way, since a mount namespace
owned by a less privileged user namespace receives its shared mounts as slaves (mount_namespaces(7)), so nothing done
inside propagates out. Container AppArmor profiles (cri-containerd's default) refuse mount(2) itself; the hiding is
then recorded as failed and is a start gate only with FETCHER_REQUIRE_HIDDEN=1.
"""
import asyncio
import contextlib
import json
import os
import pathlib
import signal
import sys

ROOT = str(pathlib.Path(__file__).resolve().parent.parent)
PASS_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "PLAYWRIGHT_BROWSERS_PATH", "TZ")
UNSHARE = os.environ.get("FETCHER_UNSHARE", "unshare")


class WorkerError(Exception):
    pass


def ns_command(args, python=None):
    return [UNSHARE, "--user", "--net", "--map-root-user", "--mount", "--propagation", "unchanged", "--",
            python or sys.executable, "-m", "claim_fetcher.sandbox", *args]


def worker_env():
    env = {k: os.environ[k] for k in PASS_ENV if k in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["PYTHONPATH"] = ROOT
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


async def run_worker(args, payload, timeout_s, python=None):
    """Run the worker with `payload` on stdin; its RESULT line as a dict. asyncio.TimeoutError after timeout_s, with
    the whole process group killed."""
    proc = await asyncio.create_subprocess_exec(*ns_command(args, python), stdin=asyncio.subprocess.PIPE,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                                                env=worker_env(), start_new_session=True, cwd="/")
    try:
        out, err = await asyncio.wait_for(proc.communicate(json.dumps(payload).encode()), timeout_s)
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), 5)
        raise
    finally:
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
    for line in reversed(out.decode("utf-8", "replace").splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    tail = err.decode("utf-8", "replace").strip().splitlines()[-5:]
    raise WorkerError(f"worker exited {proc.returncode} without a result: {' | '.join(tail)}"[:800])
