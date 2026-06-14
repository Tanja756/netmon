import os
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional

import psutil
import re
from pathlib import Path

def get_systemd_service(pid: int) -> str | None:
    """
    Возвращает имя systemd-сервиса (юнита) по PID или None,
    если определить не удалось.
    """
    cgroup_path = Path(f"/proc/{pid}/cgroup")
    if not cgroup_path.exists():
        return None
    try:
        text = cgroup_path.read_text()
        # Ищем строку вида: 0::/system.slice/xxx.service
        for line in text.splitlines():
            # Современный unified hierarchy (cgroup v2)
            if line.startswith("0::"):
                parts = line.strip().split("/")
                if parts[-1].endswith(".service"):
                    return parts[-1]
            # Старый cgroup v1 с name=systemd
            if "name=systemd:" in line:
                parts = line.strip().split("/")
                if parts[-1].endswith(".service"):
                    return parts[-1]
    except (OSError, PermissionError):
        pass
    return None

class NetTrafficCollector:
    @staticmethod
    def get_process_io(pid: int) -> Tuple[int, int]:
        io_path = f"/proc/{pid}/io"
        if not os.path.exists(io_path):
            return 0, 0
        try:
            with open(io_path) as f:
                data = f.read()
            rchar = wchar = 0
            for line in data.splitlines():
                if line.startswith("rchar:"):
                    rchar = int(line.split()[1])
                elif line.startswith("wchar:"):
                    wchar = int(line.split()[1])
            return rchar, wchar
        except Exception:
            return 0, 0


class LogCollector:
    """Сбор информации о входах в систему и uptime."""

    _MONTHS = ["jan", "feb", "mar", "apr", "may", "jun",
               "jul", "aug", "sep", "oct", "nov", "dec"]

    def __init__(self):
        self._parse_timestamp = self._make_parser()

    @staticmethod
    def _make_parser():
        def parser(line: str):
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
                try:
                    return datetime.strptime(line[:26].split("+")[0].strip(), fmt)
                except ValueError:
                    continue
            try:
                return datetime.fromisoformat(line[:25].strip())
            except Exception:
                pass
            return None
        return parser

    def _parse_syslog_ts(self, line: str):
        try:
            parts = line.split()
            if len(parts) < 3:
                return None
            mon_str = parts[0].capitalize()[:3]
            if mon_str not in self._MONTHS:
                return None
            mon = self._MONTHS.index(mon_str) + 1
            day = int(parts[1])
            time_str = parts[2]
            now = datetime.now()
            return datetime(now.year, mon, day, *map(int, time_str.split(":")))
        except Exception:
            return None

    def _parse_auth_line(self, line: str):
        ts = self._parse_timestamp(line)
        if ts is None:
            ts = self._parse_syslog_ts(line)
        if ts is None:
            return None
        line_lower = line.lower()
        if "failed password for invalid user" in line_lower:
            parts = line.split()
            try:
                return (ts, parts[parts.index("from") + 1], parts[parts.index("user") + 1], "Failed")
            except (ValueError, IndexError):
                return None
        if "failed password for" in line_lower and "invalid" not in line_lower:
            parts = line.split()
            try:
                return (ts, parts[parts.index("from") + 1], parts[parts.index("for") + 1], "Failed")
            except (ValueError, IndexError):
                return None
        if "accepted password for" in line_lower:
            parts = line.split()
            try:
                return (ts, parts[parts.index("from") + 1], parts[parts.index("for") + 1], "Accepted")
            except (ValueError, IndexError):
                return None
        if "accepted publickey for" in line_lower:
            parts = line.split()
            try:
                return (ts, parts[parts.index("from") + 1], parts[parts.index("for") + 1], "Accepted")
            except (ValueError, IndexError):
                return None
        if "authentication failure" in line_lower:
            parts = line.split()
            user = "?"
            ip = "?"
            for i, p in enumerate(parts):
                if p.startswith("rhost="):
                    ip = p.split("=", 1)[1]
                elif p.startswith("user="):
                    user = p.split("=", 1)[1]
            if user != "?" or ip != "?":
                return (ts, ip, user, "Failed")
        return None

    def _run_journalctl(self, cmd: list):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            entries = []
            for line in result.stdout.splitlines():
                if line.startswith("Hint:") or line.startswith("--"):
                    continue
                parsed = self._parse_auth_line(line)
                if parsed:
                    entries.append(parsed)
            return entries
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _read_auth_log(self, path: str):
        try:
            with open(path) as f:
                entries = []
                for line in f:
                    parsed = self._parse_auth_line(line)
                    if parsed:
                        entries.append(parsed)
                return entries
        except (FileNotFoundError, PermissionError):
            return []

    def _run_sudo(self, cmd: list):
        try:
            full_cmd = ["sudo", "-n"] + cmd
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return []
            return result.stdout.splitlines()
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return []

    def collect_login_data(self):
        """Возвращает (active_users, active_sessions, failed_1h, uptime_str, last_50_logins)."""
        users = psutil.users()
        active_users = len(set(u.name for u in users))
        active_sessions = len(users)

        login_attempts = []
        now = time.time()

        journalctl_cmd = ["journalctl", "_COMM=sshd", "-n", "500", "--no-pager", "-o", "short-iso"]
        login_attempts = self._run_journalctl(journalctl_cmd)
        if not login_attempts:
            login_attempts = self._run_journalctl(["sudo", "-n"] + journalctl_cmd)

        if not login_attempts:
            for path in ["/var/log/auth.log", "/var/log/secure"]:
                login_attempts = self._read_auth_log(path)
                if login_attempts:
                    break

        if not login_attempts:
            for path in ["/var/log/auth.log", "/var/log/secure"]:
                lines = self._run_sudo(["cat", path])
                for line in lines:
                    parsed = self._parse_auth_line(line)
                    if parsed:
                        login_attempts.append(parsed)
                if login_attempts:
                    break

        failed_1h = sum(
            1 for ts, _, _, status in login_attempts
            if status == "Failed" and (now - ts.timestamp()) < 3600
        )

        try:
            with open("/proc/uptime") as f:
                uptime_seconds = float(f.read().split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            uptime_str = f"{days}d {hours}h"
        except Exception:
            uptime_str = "?"

        display = [(ts.strftime("%H:%M"), ip, user, status)
                   for ts, ip, user, status in reversed(login_attempts[-50:])]
        return active_users, active_sessions, failed_1h, uptime_str, display