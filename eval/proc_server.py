import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_health(base_url, proc, timeout=20.0):
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            response = httpx.get(base_url + "/health", timeout=1.0)
            if response.status_code < 500:
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.1)
    output = ""
    if proc.stdout is not None:
        try:
            output = proc.stdout.read().decode("utf-8", errors="replace")
        except Exception:
            output = ""
    raise RuntimeError(
        f"server failed to start (exit={proc.poll()} error={last_error})\n{output}"
    )


def start_uvicorn(module, database, extra_env=None, uds=None):
    env = os.environ.copy()
    site = "/home/ubuntu/.local/lib/python3.12/site-packages"
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = site if not current else site + ":" + current
    env["APP_DATABASE"] = str(database)
    env.pop("SCOPE_FILE", None)
    if extra_env:
        env.update(extra_env)
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        module,
        "--log-level",
        "warning",
    ]
    if uds:
        uds_path = str(uds)
        if os.path.exists(uds_path):
            os.remove(uds_path)
        command.extend(["--uds", uds_path])
        base_url = None
    else:
        port = free_port()
        command.extend(["--host", "127.0.0.1", "--port", str(port)])
        base_url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        command,
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        if uds:
            wait_uds(str(uds), proc)
        else:
            wait_health(base_url, proc)
    except Exception:
        stop(proc)
        raise
    return proc, base_url


def wait_uds(path, proc, timeout=20.0):
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        if os.path.exists(path):
            try:
                transport = httpx.HTTPTransport(uds=path)
                client = httpx.Client(transport=transport, base_url="http://directory", timeout=1.0)
                response = client.get("/health")
                client.close()
                if response.status_code < 500:
                    return
            except Exception as exc:
                last_error = exc
        time.sleep(0.1)
    raise RuntimeError(f"uds server failed to start (exit={proc.poll()} error={last_error})")


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
