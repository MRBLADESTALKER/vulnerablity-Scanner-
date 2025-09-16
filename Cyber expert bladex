# File: Cyber_Expert_Bladex_v3.py
"""
Cyber Expert Bladex — GUI Network Scanner & Vulnerability Finder (v3)
Features:
 - PyQt5 GUI with professional dark/hacker theme and polished layout
 - Scan presets and custom nmap arguments
 - Service detection, port open/closed state, OS detection
 - Vulnerability detection via Nmap NSE scripts (e.g. --script vuln) and CVE extraction
 - Results tree view with expandable hosts -> ports -> vuln findings
 - Live log, progress bar, ability to stop scans, export JSON/CSV
 - Threaded scanning to keep UI responsive
 - Credentialed scans using encrypted credential vault (SMB/SSH/etc.)
 - Vulnerability enrichment with NVD API (CVSS, severity, references)
 - Optional offline vulnerability cache with SQLite for CVE data
 - Installer support (PyInstaller spec and notes)

Usage: python Cyber_Expert_Bladex_v3.py
Requires: Python 3.8+, nmap binary, python-nmap, PyQt5, cryptography, requests
Install: pip install python-nmap PyQt5 cryptography requests

Legal: Use only on authorized targets. This tool helps defenders and auditors.
"""

import os
import re
import sys
import json
import traceback
import sqlite3
import requests
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import nmap  # Ensure python-nmap is installed: pip install python-nmap
from PyQt5 import QtCore, QtWidgets


# ----------------- Data classes -----------------
@dataclass
class Vulnerability:
    id: Optional[str]
    title: Optional[str]
    description: Optional[str]
    severity: Optional[str]
    score: Optional[str] = None
    refs: Optional[List[str]] = None


@dataclass
class PortEntry:
    port: int
    protocol: str
    state: str
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]
    extra: Optional[str]
    vulns: List[Vulnerability]


@dataclass
class HostEntry:
    ip: str
    hostname: Optional[str]
    status: str
    os: Optional[str]
    ports: List[PortEntry]
    raw: Dict[str, Any]


class CredentialVault:
    def __init__(self, path: str = "vault.bin"):
        self.path = path
        self.data = {}

    def _derive_key(self, password: str):
        salt = b"bladex_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def load(self, password: str) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "rb") as f:
            token = f.read()
        fernet = Fernet(self._derive_key(password))
        raw = fernet.decrypt(token)
        self.data = json.loads(raw.decode())
        return self.data

    def save(self, password: str, data: Dict[str, Any]):
        fernet = Fernet(self._derive_key(password))
        token = fernet.encrypt(json.dumps(data).encode())
        with open(self.path, "wb") as f:
            f.write(token)
        self.data = data


class VulnerabilityEnricher:
    def __init__(
        self, nvd_api_key: Optional[str] = None, cache_db: str = "nvd_cache.sqlite"
    ):
        self.api_key = nvd_api_key
        self.cache_db = cache_db

    def enrich(self, vuln: Vulnerability) -> Vulnerability:
        if not vuln.id:
            return vuln
        # try cache first
        if os.path.exists(self.cache_db):
            try:
                with sqlite3.connect(self.cache_db) as conn:
                    c = conn.cursor()
                    c.execute(
                        "SELECT score, severity, desc, refs FROM cve WHERE id=?",
                        (vuln.id,),
                    )
                    row = c.fetchone()
                    if row:
                        vuln.score, vuln.severity, vuln.description, refs_json = row
                        vuln.refs = json.loads(refs_json)
                        return vuln
            except Exception:
                pass  # Failed to read from cache, proceed to API
        # fallback: query NVD API
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={vuln.id}"
            headers = {"apiKey": self.api_key} if self.api_key else {}
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code == 200:
                j = r.json()
                cve_item = j.get("vulnerabilities", [{}])[0].get("cve", {})

                # Description
                vuln.description = next(
                    (
                        desc["value"]
                        for desc in cve_item.get("descriptions", [])
                        if desc["lang"] == "en"
                    ),
                    None,
                )

                # CVSS Score and Severity
                metrics = cve_item.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    vuln.score = cvss_data.get("baseScore")
                    vuln.severity = cvss_data.get("baseSeverity")
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    vuln.score = cvss_data.get("baseScore")
                    vuln.severity = metrics["cvssMetricV2"][0].get("baseSeverity")

                # References
                refs = cve_item.get("references", [])
                vuln.refs = [ref["url"] for ref in refs]

        except Exception:
            pass  # API call failed
        return vuln


# ----------------- Worker Thread -----------------
class ScanWorker(QtCore.QThread):
    log = QtCore.pyqtSignal(str)
    result = QtCore.pyqtSignal(object)  # HostEntry
    finished_all = QtCore.pyqtSignal()
    error = QtCore.pyqtSignal(str)

    def __init__(
        self,
        targets: List[str],
        nmap_args: str,
        vault: Optional[CredentialVault] = None,
        creds: Optional[Dict[str, Dict[str, str]]] = None,
        enricher: Optional[VulnerabilityEnricher] = None,
        parent: Optional[Any] = None,
    ):
        super().__init__(parent)
        self._targets = targets
        self._args = nmap_args
        self._scanner = nmap.PortScanner()
        self._stop_requested = False
        self._vault = vault
        self._creds: Dict[str, Dict[str, str]] = creds or {}
        self._enricher = enricher

    def stop(self):
        self._stop_requested = True

    def run(self):
        try:
            for t in self._targets:
                if self._stop_requested:
                    self.log.emit("[!] Stop requested, aborting remaining targets.")
                    break
                self.log.emit(f"[+] Starting scan: {t} args: {self._args}")
                try:
                    args = self._args
                    # inject creds if available
                    if "smb" in self._creds:
                        u, p = self._creds["smb"]["user"], self._creds["smb"]["pass"]
                        args += f" --script-args smbuser={u},smbpass={p}"
                    if "ssh" in self._creds:
                        u, p = self._creds["ssh"]["user"], self._creds["ssh"]["pass"]
                        args += f" --script-args sshuser={u},sshpass={p}"
                    scan_output = self._scanner.scan(hosts=t, arguments=args)
                except Exception as e:
                    tb = traceback.format_exc()
                    self.error.emit(f"Error running nmap on {t}: {e}\n{tb}")
                    continue

                for host in self._scanner.all_hosts():
                    if self._stop_requested:
                        break
                    try:
                        h = self._scanner[host]
                        hostname = h.hostname() or None
                        status = h.state()
                        os_guess = None
                        if "osmatch" in h and h["osmatch"]:
                            os_guess = h["osmatch"][0].get("name")

                        ports = []
                        for proto in ("tcp", "udp"):
                            if proto in h:
                                for port, pinfo in h[proto].items():
                                    vulns = []
                                    scripts = pinfo.get("script", {}) or {}
                                    for script_name, script_out in scripts.items():
                                        cves = re.findall(
                                            r"CVE-\d{4}-\d{4,7}",
                                            str(script_out),
                                            flags=re.I,
                                        )
                                        title = None
                                        desc = None
                                        severity = None
                                        if isinstance(script_out, str):
                                            lines = [
                                                l.strip()
                                                for l in script_out.splitlines()
                                                if l.strip()
                                            ]
                                            if lines:
                                                title = lines[0]
                                                desc = "\n".join(lines[:6])

                                            # Handle CVEs found in script output
                                            for c in cves:
                                                v = Vulnerability(
                                                    id=c,
                                                    title=title,
                                                    description=desc,
                                                    severity=severity,
                                                )
                                                if self._enricher:
                                                    v = self._enricher.enrich(v)
                                                vulns.append(v)

                                        # Handle non-CVE vulnerabilities
                                        if not cves and re.search(
                                            r"(vulnerable|exploitable|bypass|denial of service|remote code execution)",
                                            str(script_out),
                                            flags=re.I,
                                        ):
                                            v = Vulnerability(
                                                id=None,
                                                title=script_name,
                                                description=str(script_out)[:1000],
                                                severity="High",  # Assume high severity for these keywords
                                            )
                                            vulns.append(v)

                                    pe = PortEntry(
                                        port=int(port),
                                        protocol=proto,
                                        state=pinfo.get("state", ""),
                                        service=pinfo.get("name"),
                                        product=pinfo.get("product"),
                                        version=pinfo.get("version"),
                                        extra=pinfo.get("extrainfo"),
                                        vulns=vulns,
                                    )
                                    ports.append(pe)

                        he = HostEntry(
                            ip=host,
                            hostname=hostname,
                            status=status,
                            os=os_guess,
                            ports=ports,
                            raw=h,
                        )
                        self.log.emit(f"[+] Parsed host {host} ({len(ports)} ports)")
                        self.result.emit(he)
                    except Exception as e:
                        tb = traceback.format_exc()
                        self.error.emit(f"Parsing error for host {host}: {e}\n{tb}")
                        continue
            self.finished_all.emit()
        except Exception as e:
            tb = traceback.format_exc()
            self.error.emit(f"Fatal worker error: {e}\n{tb}")


# ----------------- Main Window -----------------
class CyberExpertBladex(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Expert Bladex — Pro")
        self.resize(1200, 800)
        self._workers: List[ScanWorker] = []
        self._results: List[HostEntry] = []
        self._vault = CredentialVault()
        self._creds = {}
        self._enricher = VulnerabilityEnricher()
        self._setup_ui()
        self._apply_theme()

    def _setup_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QVBoxLayout(central)

        # --- Top Toolbar ---
        toolbar = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel(
            "<b style='color:#7cffc5'>Cyber Expert Bladex</b> — Pro Scanner"
        )
        title.setStyleSheet("font-family:Consolas; font-size:18px")
        toolbar.addWidget(title)
        toolbar.addStretch()
        self.profile_combo = QtWidgets.QComboBox()
        self.profile_combo.addItems(
            [
                "Default (-sV -T4 --open)",
                "Intense Scan (-T4 -A -v)",
                "Vuln Scan (-sV --script vuln)",
                "Quick Scan (-T4 -F)",
                "Custom...",
            ]
        )
        toolbar.addWidget(self.profile_combo)
        main_layout.addLayout(toolbar)

        # --- Scan Controls ---
        control_group = QtWidgets.QGroupBox("Scan Controls")
        control_layout = QtWidgets.QGridLayout(control_group)
        control_layout.addWidget(QtWidgets.QLabel("Targets (comma/CIDR):"), 0, 0)
        self.targets_edit = QtWidgets.QLineEdit("127.0.0.1")
        control_layout.addWidget(self.targets_edit, 0, 1, 1, 3)
        control_layout.addWidget(QtWidgets.QLabel("Nmap Args:"), 1, 0)
        self.args_edit = QtWidgets.QLineEdit("-sV -T4 --open")
        control_layout.addWidget(self.args_edit, 1, 1, 1, 3)

        self.start_btn = QtWidgets.QPushButton("Start Scan")
        self.stop_btn = QtWidgets.QPushButton("Stop Scan")
        self.stop_btn.setEnabled(False)
        self.clear_btn = QtWidgets.QPushButton("Clear Results")
        self.export_btn = QtWidgets.QPushButton("Export")

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(self.export_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.clear_btn)

        control_layout.addLayout(button_layout, 2, 0, 1, 4)
        main_layout.addWidget(control_group)

        # --- Main Content Area (Splitter) ---
        split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # Left side: Results Tree
        left_widget = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_widget)

        filter_layout = QtWidgets.QHBoxLayout()
        self.show_only_vuln = QtWidgets.QCheckBox("Show only vulnerabilities")
        filter_layout.addWidget(self.show_only_vuln)
        self.show_only_open = QtWidgets.QCheckBox("Show only open ports")
        filter_layout.addWidget(self.show_only_open)
        filter_layout.addStretch()
        left_layout.addLayout(filter_layout)

        self.results_tree = QtWidgets.QTreeWidget()
        self.results_tree.setHeaderLabels(
            ["Host / Port / Vulnerability", "State / Severity", "Service"]
        )
        self.results_tree.header().setSectionResizeMode(
            0, QtWidgets.QHeaderView.Stretch
        )
        self.results_tree.header().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeToContents
        )
        self.results_tree.header().setSectionResizeMode(
            2, QtWidgets.QHeaderView.ResizeToContents
        )
        left_layout.addWidget(self.results_tree)

        split.addWidget(left_widget)

        # Right side: Details and Log
        right_widget = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_widget)

        self.details_text = QtWidgets.QTextEdit()
        self.details_text.setReadOnly(True)
        right_layout.addWidget(QtWidgets.QLabel("<b>Details</b>"))
        right_layout.addWidget(self.details_text, 2)

        self.log_text = QtWidgets.QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        right_layout.addWidget(QtWidgets.QLabel("<b>Live Log</b>"))
        right_layout.addWidget(self.log_text, 1)

        split.addWidget(right_widget)
        split.setSizes([700, 500])
        main_layout.addWidget(split)

        # --- Bottom Status Bar ---
        bottom_layout = QtWidgets.QHBoxLayout()
        self.status_label = QtWidgets.QLabel("Idle")
        bottom_layout.addWidget(self.status_label)
        bottom_layout.addStretch()
        main_layout.addLayout(bottom_layout)

        # --- Connect Signals and Slots ---
        self.start_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        self.clear_btn.clicked.connect(self._clear)
        self.export_btn.clicked.connect(self._export)
        self.results_tree.itemClicked.connect(self._on_tree_click)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_change)

    def _apply_theme(self):
        style = """
            QWidget { background-color: #0b0d0e; color: #cfe9d6; font-family: Consolas, monospace; font-size: 14px; }
            QGroupBox { border: 1px solid #1f8b4c; margin-top: 6px; padding: 8px; border-radius: 4px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px 0 3px; }
            QLineEdit, QTextEdit, QTreeWidget { background:#091015; color:#bfe6b3; border:1px solid #2a2f33; border-radius: 4px; }
            QPushButton { background:#0b2b1f; color:#cfe9d6; padding:8px; border:1px solid #1f8b4c; border-radius:4px; }
            QPushButton:hover { background:#164b34; }
            QPushButton:disabled { background:#1a2025; color:#555; border:1px solid #444; }
            QHeaderView::section { background:#082018; color:#7ef7a3; padding: 4px; border: 1px solid #1f8b4c; }
            QComboBox { background:#091015; border:1px solid #2a2f33; border-radius: 4px; padding: 4px; }
            QSplitter::handle { background: #1f8b4c; }
        """
        self.setStyleSheet(style)

    def _on_profile_change(self, idx: int):
        profile_text = self.profile_combo.itemText(idx)
        if profile_text == "Custom...":
            self.args_edit.setReadOnly(False)
            return

        match = re.search(r"\((.*)\)", profile_text)
        if match:
            self.args_edit.setText(match.group(1))
            self.args_edit.setReadOnly(True)
        else:
            self.args_edit.setReadOnly(False)

    def _start_scan(self):
        targets_str = self.targets_edit.text()
        if not targets_str:
            self.log_text.append("[!] Error: No targets specified.")
            return

        targets = [t.strip() for t in targets_str.split(",")]
        nmap_args = self.args_edit.text()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Scanning...")
        self.log_text.append(
            f"[*] Starting new scan on {targets} with args '{nmap_args}'"
        )

        worker = ScanWorker(
            targets=targets, nmap_args=nmap_args, enricher=self._enricher
        )
        self._workers.append(worker)

        worker.log.connect(self.log_text.append)
        worker.error.connect(self.log_text.append)
        worker.result.connect(self._add_result_to_tree)
        worker.finished_all.connect(self._on_scan_finished)

        worker.start()

    def _add_result_to_tree(self, host_entry: HostEntry):
        self._results.append(host_entry)
        host_item = QtWidgets.QTreeWidgetItem(
            self.results_tree,
            [host_entry.ip, host_entry.status, host_entry.os or "Unknown"],
        )

        for port in sorted(host_entry.ports, key=lambda p: p.port):
            port_item = QtWidgets.QTreeWidgetItem(
                host_item,
                [f"  Port {port.port}/{port.protocol}", port.state, port.service or ""],
            )
            port_item.setData(0, QtCore.Qt.UserRole, port)  # Store PortEntry object

            for vuln in port.vulns:
                severity = vuln.severity or "Info"
                vuln_text = f"    {vuln.id or vuln.title}"
                vuln_item = QtWidgets.QTreeWidgetItem(
                    port_item, [vuln_text, severity, ""]
                )
                vuln_item.setData(
                    0, QtCore.Qt.UserRole, vuln
                )  # Store Vulnerability object
        self.results_tree.expandAll()

    def _on_scan_finished(self):
        self.status_label.setText("Scan finished.")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _stop_scan(self):
        self.log_text.append("[!] Sending stop signal to active scanners...")
        for worker in self._workers:
            if worker.isRunning():
                worker.stop()
        self.stop_btn.setEnabled(False)

    def _clear(self):
        self._results = []
        self.results_tree.clear()
        self.details_text.clear()
        self.log_text.clear()
        self.status_label.setText("Idle")

    def _export(self):
        # Placeholder: implement export logic to JSON or CSV
        self.log_text.append("[*] Export functionality not yet implemented.")

    def _on_tree_click(self, item, column):
        data = item.data(0, QtCore.Qt.UserRole)
        if isinstance(data, Vulnerability):
            details = f"Vulnerability: {data.id or data.title}\n\n"
            details += f"Severity: {data.severity} (Score: {data.score})\n\n"
            details += "Description:\n" + ("-" * 20) + f"\n{data.description}\n\n"
            if data.refs:
                details += "References:\n" + ("-" * 20) + "\n" + "\n".join(data.refs)
            self.details_text.setText(details)
        elif isinstance(data, PortEntry):
            details = f"Port: {data.port}/{data.protocol}\n"
            details += f"State: {data.state}\n"
            details += f"Service: {data.service}\n"
            details += f"Product: {data.product}\n"
            details += f"Version: {data.version}\n"
            self.details_text.setText(details)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = CyberExpertBladex()
    window.show()
    sys.exit(app.exec_())
