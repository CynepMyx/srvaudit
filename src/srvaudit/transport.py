from __future__ import annotations

import logging
import re
import select
import time
from uuid import uuid4

import paramiko

from srvaudit.models import CommandResult

logger = logging.getLogger("srvaudit")

MARKER_PREFIX = "SRVAUDIT"
READ_CHUNK = 4096
SHELL_INIT_TIMEOUT = 5


class HostKeyError(Exception):
    pass


class SSHConnectionError(Exception):
    pass


class StrictHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        fp = key.get_fingerprint().hex()
        fp_formatted = ":".join(fp[i : i + 2] for i in range(0, len(fp), 2))
        raise HostKeyError(
            f"Unknown host key for {hostname}: {fp_formatted}\n"
            f"Verify and run with --accept-host-key to trust it,\n"
            f"or add to ~/.ssh/known_hosts manually."
        )


class ShellTransport:
    def __init__(
        self,
        host: str,
        user: str,
        port: int = 22,
        key_path: str = None,
        password: str = None,
        accept_host_key: bool = False,
        known_hosts: str = None,
        sudo: bool = False,
        command_timeout: int = 15,
        connect_timeout: int = 10,
    ):
        self.host = host
        self.user = user
        self.port = port
        self.sudo = sudo
        self.command_timeout = command_timeout

        self.client = paramiko.SSHClient()

        if known_hosts:
            self.client.load_host_keys(known_hosts)
        else:
            self.client.load_system_host_keys()

        if accept_host_key:
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            self.client.set_missing_host_key_policy(StrictHostKeyPolicy())

        connect_kwargs = {
            "hostname": host,
            "port": port,
            "username": user,
            "timeout": connect_timeout,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if key_path:
            connect_kwargs["key_filename"] = key_path
        if password:
            connect_kwargs["password"] = password

        try:
            self.client.connect(**connect_kwargs)
        except paramiko.AuthenticationException as e:
            raise SSHConnectionError(f"Authentication failed for {user}@{host}: {e}")
        except Exception as e:
            raise SSHConnectionError(f"Cannot connect to {host}:{port}: {e}")

        self.channel = self.client.invoke_shell(width=200, height=50)
        self.channel.settimeout(0)
        self._drain_initial_output()

    def _drain_initial_output(self):
        time.sleep(0.5)
        deadline = time.monotonic() + SHELL_INIT_TIMEOUT
        while time.monotonic() < deadline:
            if self.channel.recv_ready():
                self.channel.recv(READ_CHUNK)
            else:
                time.sleep(0.1)
                if not self.channel.recv_ready():
                    break

    def execute(self, command: str, timeout: int = None) -> CommandResult:
        t = timeout or self.command_timeout
        marker = f"{MARKER_PREFIX}_{uuid4().hex[:8]}"

        cmd = command
        if self.sudo:
            cmd = f"sudo {cmd}"

        wrapped = f"{cmd}; echo {marker}$?{marker}\n"
        self.channel.sendall(wrapped.encode())

        output = self._read_until_marker(marker, t)

        if output is None:
            return CommandResult(
                command=command,
                stdout="",
                return_code=-1,
                timed_out=True,
            )

        stdout, return_code = self._parse_output(output, marker, wrapped.strip())
        return CommandResult(
            command=command,
            stdout=stdout,
            return_code=return_code,
        )

    def _read_until_marker(self, marker: str, timeout: int) -> str:
        buf = ""
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            ready = select.select([self.channel], [], [], min(remaining, 0.5))
            if ready[0]:
                try:
                    chunk = self.channel.recv(READ_CHUNK).decode("utf-8", errors="replace")
                    buf += chunk
                    if marker in buf and buf.count(marker) >= 2:
                        return buf
                except Exception:
                    break
            if self.channel.closed:
                break

        if marker in buf and buf.count(marker) >= 2:
            return buf
        return None

    def _parse_output(self, raw: str, marker: str, sent_command: str) -> tuple:
        lines = []
        return_code = -1

        pattern = re.compile(re.escape(marker) + r"(\d+)" + re.escape(marker))
        match = pattern.search(raw)
        if match:
            return_code = int(match.group(1))

        for line in raw.splitlines():
            if marker in line:
                continue
            if sent_command and line.strip() == sent_command.strip():
                continue
            lines.append(line)

        stdout = "\n".join(lines).strip()

        if len(stdout) > 65536:
            stdout = stdout[:65536]
            logger.warning("Output truncated to 64KB for command")

        return stdout, return_code

    def close(self):
        try:
            self.channel.close()
        except Exception:
            pass
        try:
            self.client.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
