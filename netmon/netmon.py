#!/usr/bin/env python3
"""
netmon.py — профессиональный монитор сетевых соединений (htop‑подобный интерфейс).
"""

import socket
import asyncio
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional

import psutil
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Header, Footer, Static, DataTable, Input
from textual import events
from textual.widgets._data_table import RowKey
from textual.coordinate import Coordinate
from textual.timer import Timer

from .help_screen import HelpScreen
from .collectors import NetTrafficCollector, LogCollector, get_systemd_service
from .openvpn_monitor import OpenVPNMonitor


class NetMonitor(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    #topbar {
        height: 3;
        background: $boost;
        color: $text;
        padding: 0 1;
        content-align: left middle;
    }
    #main-layout {
        height: 1fr;
    }
    #left-panel {
        width: 60%;
        border: round $primary;
        padding: 0;
    }
    #right-panel {
        width: 40%;
        border: round $accent;
        padding: 1;
        background: $surface;
    }
    #client-table-container {
        height: 1fr;
        border-top: solid $primary;
        margin: 0;
    }
    #search {
        dock: bottom;
        display: none;
        background: $surface;
        border: solid $primary;
    }
    #status {
        height: 1;
        background: $panel;
        color: $text-muted;
        padding: 0 1;
    }
    #server-detail {
        height: 1fr;
    }
    #info-table {
        height: 4;
        border: round yellow;
        margin: 0 1;
    }
    #login-table {
        height: 10;
        border: round $primary;
        margin: 0 1;
    }
    DataTable {
        height: 1fr;
    }
    """

    update_interval = 2.0
    auto_update = reactive(True)

    def __init__(self):
        super().__init__()
        self.collector = NetTrafficCollector()
        self.openvpn_monitor = OpenVPNMonitor()
        self.log_collector = LogCollector()
        self.prev_io: Dict[int, Tuple[int, int]] = {}
        self.servers: List[dict] = []
        self.current_server_key: Optional[Tuple] = None
        self.client_table_visible = True
        self.search_filter = ""
        self.refresh_timer: Optional[Timer] = None
        self._cpu_cache: Dict[int, float] = {}
        self.sort_column = 0
        self.sort_reverse = False

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Servers: 0 | Clients: 0 | Total traffic: 0 B/s", id="topbar")
        with Horizontal(id="main-layout"):
            with Vertical(id="left-panel"):
                yield DataTable(id="servers-table")
                yield Container(
                    DataTable(id="client-table"),
                    id="client-table-container"
                )
            with Vertical(id="right-panel"):
                yield Static("Select a server", id="server-detail")
                yield DataTable(id="info-table")
                yield DataTable(id="login-table")
        yield Input(placeholder="Search (PID/name/port)...", id="search")
        yield Static("Space Pause | / Search | S Toggle clients | ? Help | Q Quit", id="status")
        yield Footer()

    def on_mount(self):
        self.table = self.query_one("#servers-table", DataTable)
        self.client_table = self.query_one("#client-table", DataTable)
        self.right_panel = self.query_one("#right-panel", Vertical)
        self.server_detail = self.query_one("#server-detail", Static)
        self.search_field = self.query_one("#search", Input)
        self.top_bar = self.query_one("#topbar", Static)
        self.status_bar = self.query_one("#status", Static)

        self.table.add_columns("PID", "PROCESS", "PROTO", "LOCAL", "PORT", "CLIENTS", "RX/s", "TX/s")
        self.table.cursor_type = "row"
        self.table.zebra_stripes = True

        self.client_table.add_columns("Remote Addr", "State", "Client PID")
        self.client_table.zebra_stripes = True

        self.info_table = self.query_one("#info-table", DataTable)
        self.login_table = self.query_one("#login-table", DataTable)
        self.info_table.add_columns("Users", "Sessions", "Failed(1h)", "Uptime")
        self.login_table.add_columns("Time", "IP", "Username", "Status")
        self.login_table.zebra_stripes = True

        # Первичное заполнение
        self._update_login_info()
        self.refresh_timer = self.set_interval(
            self.update_interval, self.refresh_data, pause=not self.auto_update
        )
        self.update_status()

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    @staticmethod
    def format_bytes(b: int) -> str:
        if b < 1024:
            return f"{b}B"
        elif b < 1024**2:
            return f"{b//1024}KiB"
        elif b < 1024**3:
            return f"{b//(1024**2)}MiB"
        else:
            return f"{b//(1024**3)}GiB"

    @staticmethod
    def traffic_color(rate: float) -> str:
        if rate > 50 * 1024 * 1024:
            return "red"
        elif rate > 5 * 1024 * 1024:
            return "yellow"
        else:
            return "green"

    @staticmethod
    def client_state_color(state: str) -> str:
        state = state.lower()
        if state == "established":
            return "green"
        elif "time_wait" in state or "close" in state:
            return "dim"
        return "white"

    # ------------------------------------------------------------------
    # Сбор данных
    # ------------------------------------------------------------------
    async def collect_servers_and_clients(self):
        try:
            all_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            self.update_status("No permission, run with sudo")
            return [], 0, (0, 0, 0, 0)

        # Имена процессов
        proc_names = {}
        for p in psutil.process_iter(["pid", "name"]):
            pid = p.info["pid"]
            name = p.info["name"] or "unknown"
            try:
                service = get_systemd_service(pid)
                if service:
                    name = f"{name} ({service})"
            except Exception:
                pass
            proc_names[pid] = name

        servers_raw = []
        server_addrs = set()
        server_pids = set()

        for conn in all_conns:
            if not conn.laddr:
                continue
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            ip, port = conn.laddr
            pid = conn.pid or 0
            name = proc_names.get(pid, "?")
            if proto == "TCP" and conn.status == "LISTEN":
                servers_raw.append((proto, port, pid, name, ip))
                server_addrs.add((proto, ip, port))
                server_pids.add((proto, ip, port, pid))
            elif proto == "UDP":
                if not conn.raddr or conn.raddr.ip in ("0.0.0.0", "::") or conn.raddr.port == 0:
                    servers_raw.append((proto, port, pid, name, ip))
                    server_addrs.add((proto, ip, port))
                    server_pids.add((proto, ip, port, pid))

        server_index = defaultdict(list)
        for proto, port, pid, name, ip in servers_raw:
            server_index[(proto, ip, port)].append((pid, name))

        clients_map = defaultdict(list)
        for conn in all_conns:
            if not conn.laddr:
                continue
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            ip, port = conn.laddr
            pid = conn.pid or 0
            if (proto, ip, port, pid) in server_pids:
                continue
            match_key = None
            if (proto, ip, port) in server_addrs:
                match_key = (proto, ip, port)
            else:
                for srv_ip in ("0.0.0.0", "::"):
                    if (proto, srv_ip, port) in server_addrs:
                        match_key = (proto, srv_ip, port)
                        break
            if match_key:
                for srv_pid, srv_name in server_index[match_key]:
                    if conn.laddr == (ip, port) and conn.pid == srv_pid:
                        continue
                    matched = (proto, srv_pid, port)
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*:*"
                    state = conn.status if conn.status else "-"
                    clients_map[matched].append((raddr, state, conn.pid or 0))

        current_io = {}
        for _, _, pid, _, _ in servers_raw:
            if pid and pid not in current_io:
                current_io[pid] = self.collector.get_process_io(pid)

        alive_pids = {s[2] for s in servers_raw if s[2]}
        for pid in alive_pids:
            if pid not in self._cpu_cache:
                try:
                    p = psutil.Process(pid)
                    self._cpu_cache[pid] = p.cpu_percent(None)
                except psutil.NoSuchProcess:
                    self._cpu_cache[pid] = 0.0
            else:
                try:
                    p = psutil.Process(pid)
                    self._cpu_cache[pid] = p.cpu_percent(None)
                except psutil.NoSuchProcess:
                    self._cpu_cache[pid] = 0.0
        for pid in list(self._cpu_cache.keys()):
            if pid not in alive_pids:
                del self._cpu_cache[pid]

        servers = []
        total_rx_rate = total_tx_rate = total_rx_cum = total_tx_cum = 0
        for proto, port, pid, name, ip in servers_raw:
            rx_total, tx_total = current_io.get(pid, (0, 0))
            total_rx_cum += rx_total
            total_tx_cum += tx_total
            prev_rx, prev_tx = self.prev_io.get(pid, (rx_total, tx_total))
            rx_rate = max(0, rx_total - prev_rx) / self.update_interval
            tx_rate = max(0, tx_total - prev_tx) / self.update_interval
            total_rx_rate += rx_rate
            total_tx_rate += tx_rate

            clients_list = clients_map.get((proto, pid, port), [])

            is_openvpn = (name.lower() == "openvpn") or ("openvpn" in name.lower())
            if not is_openvpn and pid:
                try:
                    p = psutil.Process(pid)
                    cmdline_lower = " ".join(p.cmdline()).lower()
                    if "openvpn" in cmdline_lower or "ovpn-server" in cmdline_lower:
                        is_openvpn = True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            ovpn_clients = []
            if is_openvpn and pid:
                mgmt_host = "127.0.0.1"
                mgmt_port = 5555
                found = False

                try:
                    p = psutil.Process(pid)
                    cmdline = p.cmdline()
                    for i, arg in enumerate(cmdline):
                        if arg == "--management" and i + 2 < len(cmdline):
                            mgmt_host = cmdline[i+1]
                            try:
                                mgmt_port = int(cmdline[i+2])
                                found = True
                            except ValueError:
                                pass
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                if not found:
                    cfg_host, cfg_port = self.openvpn_monitor.find_management_from_config(pid)
                    if cfg_host and cfg_port:
                        mgmt_host, mgmt_port = cfg_host, cfg_port

                ovpn_clients = await self.openvpn_monitor.get_openvpn_clients(pid, mgmt_host, mgmt_port)

                if ovpn_clients:
                    clients_list = [
                        (c["real_address"], "ESTABLISHED", c["common_name"])
                        for c in ovpn_clients
                    ]

            servers.append({
                "pid": pid,
                "name": name,
                "proto": proto,
                "local_ip": ip,
                "port": port,
                "rx_rate": rx_rate,
                "tx_rate": tx_rate,
                "clients": clients_list,
                "client_count": len(clients_list),
                "ovpn_clients": ovpn_clients,
            })
        self.prev_io = current_io
        total_clients = sum(s["client_count"] for s in servers)
        return servers, total_clients, (total_rx_rate, total_tx_rate, total_rx_cum, total_tx_cum)

    # ------------------------------------------------------------------
    # Обновление UI
    # ------------------------------------------------------------------
    def _update_login_info(self):
        au, sess, fail, up, logins = self.log_collector.collect_login_data()
        self.info_table.clear()
        self.info_table.add_row(str(au), str(sess), str(fail), up)
        self.login_table.clear()
        for time_str, ip, user, status in logins:
            color = "red" if status == "Failed" else "green"
            self.login_table.add_row(time_str, ip, user, f"[{color}]{status}[/]")

    async def refresh_data(self):
        servers, total_clients, (total_rx, total_tx, total_rx_cum, total_tx_cum) = await self.collect_servers_and_clients()
        self.servers = servers

        self.top_bar.update(
            f"Servers: {len(servers)} | Clients: {total_clients} | "
            f"⬇ {self.format_bytes(int(total_rx))}/s  ⬆ {self.format_bytes(int(total_tx))}/s | "
            f"Σ⬇ {self.format_bytes(total_rx_cum)}  Σ⬆ {self.format_bytes(total_tx_cum)}"
        )

        self._update_login_info()

        filtered = servers
        if self.search_filter:
            flt = self.search_filter.lower()
            filtered = [
                s for s in servers
                if flt in str(s["pid"]).lower()
                or flt in s["name"].lower()
                or flt in str(s["port"])
            ]

        def sort_key(srv):
            col = self.sort_column
            if col == 0: return srv["pid"]
            elif col == 1: return srv["name"].lower()
            elif col == 2: return srv["proto"]
            elif col == 3: return srv["local_ip"]
            elif col == 4: return srv["port"]
            elif col == 5: return srv["client_count"]
            elif col == 6: return srv["rx_rate"]
            elif col == 7: return srv["tx_rate"]
            return 0
        filtered.sort(key=sort_key, reverse=self.sort_reverse)

        unique_servers = {}
        for srv in filtered:
            key = (srv['pid'], srv['proto'], srv['local_ip'], srv['port'])
            unique_servers.setdefault(key, srv)
        filtered_unique = list(unique_servers.values())

        previous_selected_key = self.current_server_key
        cursor_row_key = None
        scroll_y = self.table.scroll_y
        if self.table.row_count > 0:
            try:
                cursor_row_key = self.table.coordinate_to_cell_key(self.table.cursor_coordinate).row_key
            except Exception:
                pass

        self.table.clear()
        for srv in filtered_unique:
            key = (srv['pid'], srv['proto'], srv['local_ip'], srv['port'])
            rate = max(srv["rx_rate"], srv["tx_rate"])
            color = self.traffic_color(rate)
            rx_str = f"[{color}]{self.format_bytes(int(srv['rx_rate']))}/s[/]"
            tx_str = f"[{color}]{self.format_bytes(int(srv['tx_rate']))}/s[/]"
            self.table.add_row(
                str(srv["pid"]),
                srv["name"],
                srv["proto"],
                srv["local_ip"],
                str(srv["port"]),
                str(srv["client_count"]),
                rx_str,
                tx_str,
                key=key
            )

        restored = False
        if previous_selected_key and self.table.row_count > 0:
            try:
                row_index = self.table.get_row_index(RowKey(previous_selected_key))
                self.table.move_cursor(row=row_index, column=0)
                restored = True
            except KeyError:
                self.current_server_key = None

        if not restored and cursor_row_key is not None and self.table.row_count > 0:
            try:
                row_index = self.table.get_row_index(cursor_row_key)
                self.table.move_cursor(row=row_index, column=0)
                restored = True
            except KeyError:
                pass

        if not restored and self.table.row_count > 0:
            self.table.move_cursor(row=0, column=0)

        if scroll_y < self.table.row_count:
            self.table.scroll_to(y=scroll_y, animate=False)
        else:
            self.table.scroll_to(y=max(0, self.table.row_count - 1), animate=False)

        if self.current_server_key and self.client_table_visible:
            pid, proto, ip, port = self.current_server_key
            for srv in servers:
                if (srv["pid"] == pid and srv["proto"] == proto and
                    srv["local_ip"] == ip and srv["port"] == port):
                    self.show_client_table(srv)
                    break
            else:
                self.clear_client_table()
        else:
            self.clear_client_table()

        self.update_status(f"Updated at {datetime.now().strftime('%H:%M:%S')}")

    # ------------------------------------------------------------------
    # Отображение клиентов
    # ------------------------------------------------------------------
    def show_client_table(self, server: dict):
        if not self.client_table_visible:
            self.clear_client_table(columns=True)
            return

        ovpn_clients = server.get("ovpn_clients", [])
        scroll_y = self.client_table.scroll_y

        if ovpn_clients:
            self.client_table.clear(columns=True)
            self.client_table.add_columns(
                "Common Name", "Remote Address", "RX", "TX", "Connected Since"
            )
            for c in ovpn_clients:
                rx = self.format_bytes(int(c["bytes_received"]))
                tx = self.format_bytes(int(c["bytes_sent"]))
                self.client_table.add_row(
                    c["common_name"],
                    c["real_address"],
                    rx,
                    tx,
                    c["connected_since"],
                )
        else:
            self.client_table.clear(columns=True)
            self.client_table.add_columns("Remote Addr", "State", "Client PID")
            for raddr, state, client_pid in server["clients"]:
                color = self.client_state_color(state)
                self.client_table.add_row(
                    raddr,
                    f"[{color}]{state}[/]",
                    str(client_pid) if client_pid else "-",
                )

        if scroll_y < self.client_table.row_count:
            self.client_table.scroll_to(y=scroll_y, animate=False)
        else:
            self.client_table.scroll_to(y=max(0, self.client_table.row_count - 1), animate=False)

    def clear_client_table(self):
        self.client_table.clear(columns=True)

    # ------------------------------------------------------------------
    # Обработчики событий
    # ------------------------------------------------------------------
    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        key = event.row_key
        if key is None:
            return
        pid, proto, ip, port = key.value
        self.current_server_key = (pid, proto, ip, port)
        for srv in self.servers:
            if (srv["pid"] == pid and srv["proto"] == proto and
                srv["local_ip"] == ip and srv["port"] == port):
                self.show_client_table(srv)
                self.show_process_details(srv)
                break

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected):
        if self.sort_column == event.column_index:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = event.column_index
            self.sort_reverse = False
        self.run_worker(self.refresh_data())

    def show_process_details(self, server: dict):
        pid = server["pid"]
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                cpu = self._cpu_cache.get(pid, p.cpu_percent(interval=0))
                mem_mb = p.memory_info().rss // (1024 * 1024)
                threads = p.num_threads()
                user = p.username()
                exe = p.exe() or "?"
                cmdline = " ".join(p.cmdline())
                if len(cmdline) > 2000:
                    cmdline = cmdline[:2000] + "…"
                rx = self.format_bytes(int(server["rx_rate"]))
                tx = self.format_bytes(int(server["tx_rate"]))
            text = f"""
PID:       {pid}
USER:      {user}
PROTO:     {server['proto']}
PORT:      {server['port']}
LOCAL:     {server['local_ip']}

CPU:       {cpu:.1f}%
MEM:       {mem_mb} MB
THREADS:   {threads}

RX rate:   {rx}/s
TX rate:   {tx}/s

EXE:
{exe}

CMD:
{cmdline}
"""
            self.server_detail.update(text)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.server_detail.update(f"Process {pid} no longer accessible")

    def action_search(self):
        self.search_field.display = True
        self.search_field.focus()

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "search":
            self.search_filter = event.value.strip().lower()
            self.search_field.display = False
            self.run_worker(self.refresh_data())

    def reset_filter(self):
        self.search_filter = ""
        self.search_field.display = False
        self.run_worker(self.refresh_data())

    def action_toggle_update(self):
        self.auto_update = not self.auto_update
        if self.refresh_timer:
            if self.auto_update:
                self.refresh_timer.resume()
            else:
                self.refresh_timer.pause()
        self.update_status()

    def action_toggle_client_table(self):
        self.client_table_visible = not self.client_table_visible
        if self.client_table_visible and isinstance(self.current_server_key, tuple):
            pid, proto, ip, port = self.current_server_key
            for srv in self.servers:
                if (srv["pid"] == pid and srv["proto"] == proto and
                    srv["local_ip"] == ip and srv["port"] == port):
                    self.show_client_table(srv)
                    break
        else:
            self.clear_client_table()
        self.update_status()

    def action_quit(self):
        self.exit()

    def action_show_help(self):
        self.push_screen(HelpScreen())

    def update_status(self, msg=""):
        if not msg:
            self.status_bar.update(
                f"Auto-update: {'ON' if self.auto_update else 'OFF'} | "
                f"Clients: {'visible' if self.client_table_visible else 'hidden'} | "
                f"Space Pause | / Search | S Toggle clients | ? Help | Q Quit"
            )
        else:
            self.status_bar.update(msg)

    def on_key(self, event: events.Key):
        if event.key == "escape" and self.search_field.display:
            self.reset_filter()
        elif event.key == "/":
            self.action_search()
        elif event.key == "s" or event.key == "S":
            self.action_toggle_client_table()
        elif event.key == " ":
            self.action_toggle_update()
        elif event.key == "q" or event.key == "Q":
            self.action_quit()
        elif event.key == "?":
            self.action_show_help()


if __name__ == "__main__":
    app = NetMonitor()
    app.run()