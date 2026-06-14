import os
import time
import asyncio
from typing import Dict, List, Tuple

import psutil


class OpenVPNMonitor:
    def __init__(self):
        self._cache: Dict[Tuple[int, str, int], Tuple[List[dict], float]] = {}
        self._cache_ttl = 5.0

    async def get_openvpn_clients(self, pid: int, mgmt_host: str, mgmt_port: int) -> List[dict]:
        """Возвращает детальный список клиентов с management-интерфейса."""
        now = time.time()
        cache_key = (pid, mgmt_host, mgmt_port)
        if cache_key in self._cache:
            clients, cached_time = self._cache[cache_key]
            if now - cached_time < self._cache_ttl:
                return clients

        clients = await self._query_management_interface(pid, mgmt_host, mgmt_port)
        self._cache[cache_key] = (clients, now)
        return clients

    async def _query_management_interface(self, pid: int, mgmt_host: str, mgmt_port: int) -> List[dict]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(mgmt_host, mgmt_port), timeout=2.0
            )

            # Пропускаем баннер
            await asyncio.wait_for(reader.readline(), timeout=2.0)

            writer.write(b"status 3\n")
            await writer.drain()

            chunks = []
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if not line:
                    break
                text = line.decode(errors="ignore")
                chunks.append(text)
                if text.strip() == "END":
                    break

            writer.close()
            await writer.wait_closed()

            resp_str = "".join(chunks)
            if "ENTER PASSWORD:" in resp_str:
                return []
            return self._parse_status_response(resp_str)
        except Exception:
            return []

    def _parse_status_response(self, response: str) -> List[dict]:
        """
        Парсит ответ management-интерфейса.
        Поддерживает вывод status 2/3 (поля через табуляцию) и старый формат.
        """
        clients = []
        in_client_list = False

        for line in response.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("HEADER"):
                if "CLIENT_LIST" in line:
                    in_client_list = True
                elif "ROUTING_TABLE" in line:
                    in_client_list = False
                continue

            if line.startswith("GLOBAL_STATS") or line == "END":
                in_client_list = False
                continue

            if in_client_list and line.startswith("CLIENT_LIST"):
                parts = line.split('\t')  # строго по табуляции
                if len(parts) >= 9:
                    common_name = parts[1]
                    real_address = parts[2]
                    bytes_recv = parts[5]
                    bytes_sent = parts[6]
                    connected_since = parts[7] + " " + parts[8] if len(parts) > 8 else parts[7]
                    clients.append({
                        "common_name": common_name,
                        "real_address": real_address,
                        "bytes_received": bytes_recv,
                        "bytes_sent": bytes_sent,
                        "connected_since": connected_since,
                    })
                elif len(parts) >= 5:
                    clients.append({
                        "common_name": parts[1],
                        "real_address": parts[2],
                        "bytes_received": parts[3],
                        "bytes_sent": parts[4],
                        "connected_since": parts[5] if len(parts) > 5 else "",
                    })
        return clients

    def clear_cache(self, pid: int = None):
        if pid:
            keys_to_remove = [k for k in self._cache if k[0] == pid]
            for k in keys_to_remove:
                self._cache.pop(k, None)
        else:
            self._cache.clear()

    def find_management_from_config(self, pid: int) -> Tuple[str, int]:
        """Ищет директиву management в конфигурационном файле OpenVPN."""
        try:
            p = psutil.Process(pid)
            cmdline = p.cmdline()
            config_file = None
            for i, arg in enumerate(cmdline):
                if arg == '--config' and i + 1 < len(cmdline):
                    config_file = cmdline[i + 1]
                    break
            if not config_file:
                return None, None
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('management '):
                        parts = line.split()
                        if len(parts) >= 3:
                            host = parts[1]
                            try:
                                port = int(parts[2])
                            except ValueError:
                                continue
                            return host, port
        except Exception:
            pass
        return None, None