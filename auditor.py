from __future__ import annotations
import argparse
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

SKIP_DIRS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/mnt",
    "/media",
    "/lost+found",
}

SCAN_DIRS = [
    "/etc",
    "/home",
    "/root",
    "/opt",
    "/srv",
    "/var",
    "/tmp",
    "/usr/local",
]

KNOWN_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    111: "RPCbind",
    139: "NetBIOS",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh/syslog",
    873: "rsync",
    1080: "SOCKS proxy",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    2375: "Docker API",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

HIGH_RISK_PORTS = {21, 23, 139, 445, 2375, 3306, 5432, 6379, 9200, 11211, 27017}

SUSPICIOUS_CRON_PATTERNS = [
    r"/tmp/",
    r"/var/tmp/",
    r"chmod\s+777",
    r"chmod\s+666",
    r"\bcurl\b",
    r"\bwget\b",
    r"\bnc\b",
    r"\bnetcat\b",
    r"\bbash\s+-c\b",
    r"\bsh\s+-c\b",
    r">\s*/dev/tcp/",
]

CRON_TARGETS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
]

SAFE_WORLD_WRITABLE_DIRS = {"/tmp", "/var/tmp", "/dev/shm"}
MAX_TEXT_FILE_SIZE = 1024 * 1024


Issue = Dict[str, str]


def run_command(command: Sequence[str]) -> str:
    """Run a command and return stdout. Empty string on failure."""
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    return result.stdout or ""


def is_skipped_path(path: str) -> bool:
    """Return True if the path belongs to a virtual or irrelevant tree."""
    absolute = os.path.abspath(path)
    return any(absolute == base or absolute.startswith(base + os.sep) for base in SKIP_DIRS)


def deduplicate(items: List[Issue]) -> List[Issue]:
    """Remove duplicate dictionaries while preserving order."""
    seen = set()
    unique: List[Issue] = []
    for item in items:
        marker = tuple(sorted(item.items()))
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(item)
    return unique


def read_text_file(path: Path) -> str:
    """Read a small text file, skipping binary files and very large files."""
    try:
        if not path.is_file():
            return ""
        if path.stat().st_size > MAX_TEXT_FILE_SIZE:
            return ""
        with path.open("rb") as handle:
            sample = handle.read(4096)
            if b"\x00" in sample:
                return ""
    except OSError:
        return ""

    for encoding in ("utf-8", "latin-1", "cp1251"):
        try:
            return path.read_text(encoding=encoding, errors="ignore")
        except OSError:
            continue
    return ""


def parse_listening_ports() -> List[Issue]:
    """Parse listening sockets from ss or netstat output."""
    output = run_command(["ss", "-tulpn"])
    if not output:
        output = run_command(["netstat", "-tulpn"])

    findings: List[Issue] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        lower = line.lower()
        if not line:
            continue
        if "listen" not in lower and not lower.startswith("udp"):
            continue

        match = re.search(r":(\d+)\s", line + " ")
        if not match:
            continue

        port = int(match.group(1))
        process_match = re.search(r'users:\(\("([^"]+)"', line)
        process_name = process_match.group(1) if process_match else "-"

        if "127.0.0.1:" in line or "[::1]:" in line:
            bind_scope = "localhost"
        elif "0.0.0.0:" in line or "[::]:" in line or "*:" in line:
            bind_scope = "all_interfaces"
        else:
            bind_scope = "specific_interface"

        service_name = KNOWN_PORTS.get(port, "Unknown or uncommon service")
        severity = "info"
        if port in KNOWN_PORTS:
            severity = "medium"
        if port in HIGH_RISK_PORTS and bind_scope == "all_interfaces":
            severity = "high"

        findings.append(
            {
                "type": "open_port",
                "severity": severity,
                "target": f"port {port}",
                "details": f"service={service_name}; bind={bind_scope}; process={process_name}; raw={line}",
            }
        )

    return deduplicate(findings)


def iter_scan_paths() -> Iterable[str]:
    """Yield file system paths from the configured trees."""
    for base in SCAN_DIRS:
        if not os.path.exists(base) or is_skipped_path(base):
            continue

        for root, dirs, files in os.walk(base, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if not is_skipped_path(os.path.join(root, d))]

            for directory_name in dirs:
                yield os.path.join(root, directory_name)
            for file_name in files:
                yield os.path.join(root, file_name)


def check_permissions() -> List[Issue]:
    """Find files and directories with dangerous permissions."""
    findings: List[Issue] = []

    for path_str in iter_scan_paths():
        try:
            st = os.lstat(path_str)
        except OSError:
            continue

        mode = stat.S_IMODE(st.st_mode)
        is_directory = stat.S_ISDIR(st.st_mode)

        if is_directory:
            if mode & 0o002:
                severity = "medium" if path_str in SAFE_WORLD_WRITABLE_DIRS else "high"
                sticky = bool(mode & stat.S_ISVTX)
                findings.append(
                    {
                        "type": "world_writable_directory",
                        "severity": severity if not sticky else "medium",
                        "target": path_str,
                        "details": f"mode={oct(mode)}; sticky_bit={'yes' if sticky else 'no'}",
                    }
                )
            continue

        if mode & 0o002:
            findings.append(
                {
                    "type": "world_writable_file",
                    "severity": "high",
                    "target": path_str,
                    "details": f"mode={oct(mode)}",
                }
            )

        if mode == 0o777:
            findings.append(
                {
                    "type": "file_mode_777",
                    "severity": "high",
                    "target": path_str,
                    "details": "file has mode 0777",
                }
            )

        if mode == 0o666:
            findings.append(
                {
                    "type": "file_mode_666",
                    "severity": "high",
                    "target": path_str,
                    "details": "file has mode 0666",
                }
            )

    return deduplicate(findings)


def collect_cron_files() -> List[Path]:
    """Return cron-related files that exist on the current host."""
    files: List[Path] = []
    for target in CRON_TARGETS:
        path = Path(target)
        if not path.exists():
            continue
        if path.is_file():
            files.append(path)
            continue
        if path.is_dir():
            try:
                for item in path.rglob("*"):
                    if item.is_file():
                        files.append(item)
            except OSError:
                continue
    return files


def check_cron() -> List[Issue]:
    """Inspect cron files for risky permissions and suspicious commands."""
    findings: List[Issue] = []

    for cron_file in collect_cron_files():
        try:
            mode = stat.S_IMODE(cron_file.stat().st_mode)
            if mode & 0o002:
                findings.append(
                    {
                        "type": "world_writable_cron",
                        "severity": "high",
                        "target": str(cron_file),
                        "details": f"mode={oct(mode)}",
                    }
                )
        except OSError:
            pass

        content = read_text_file(cron_file)
        if not content:
            continue

        for pattern in SUSPICIOUS_CRON_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(
                    {
                        "type": "suspicious_cron_content",
                        "severity": "medium",
                        "target": str(cron_file),
                        "details": f"matched_pattern={pattern}",
                    }
                )

    return deduplicate(findings)


def format_section(title: str, findings: List[Issue]) -> str:
    """Build a printable section of the final report."""
    lines = ["=" * 80, title, "=" * 80]
    if not findings:
        lines.append("Nothing found.")
        return "\n".join(lines)

    for item in findings:
        lines.append(f"[{item['severity'].upper()}] {item['type']}")
        lines.append(f"target: {item['target']}")
        lines.append(f"details: {item['details']}")
        lines.append("-" * 80)
    return "\n".join(lines)


def build_report(port_findings: List[Issue], permission_findings: List[Issue], cron_findings: List[Issue]) -> str:
    """Combine all sections into a single text report."""
    parts = [
        "Linux basic audit report",
        format_section("OPEN PORTS", port_findings),
        format_section("DANGEROUS FILE AND DIRECTORY PERMISSIONS", permission_findings),
        format_section("CRON CHECK", cron_findings),
        "=" * 80,
        "SUMMARY",
        "=" * 80,
        f"Open ports: {len(port_findings)}",
        f"Permission issues: {len(permission_findings)}",
        f"Cron issues: {len(cron_findings)}",
    ]
    return "\n\n".join(parts) + "\n"


def save_report(report_text: str, output_path: str) -> None:
    """Write the report to disk."""
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(report_text)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Basic Linux auditor")
    parser.add_argument(
        "-o",
        "--output",
        default="audit_report.txt",
        help="path to the output report file (default: audit_report.txt)",
    )
    return parser.parse_args()


def main() -> None:
    """Program entry point."""
    args = parse_args()

    port_findings = parse_listening_ports()
    permission_findings = check_permissions()
    cron_findings = check_cron()

    report_text = build_report(port_findings, permission_findings, cron_findings)
    print(report_text, end="")
    save_report(report_text, args.output)
    print(f"Report saved to: {args.output}")


if __name__ == "__main__":
    main()
