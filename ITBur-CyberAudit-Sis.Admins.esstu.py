#!/usr/bin/env python3
"""
ITBur-CyberAudit-Sis.Admins.esstu
Автоматический аудитор безопасности Linux
Версия: 2.0
"""

import os
import sys
import json
import subprocess
import re
import pwd
import grp
import socket
import argparse
from datetime import datetime
from typing import Dict, List, Tuple, Any
import concurrent.futures
from tabulate import tabulate
import colorama
from colorama import Fore, Back, Style

colorama.init(autoreset=True)

APP_NAME = "ITBur-CyberAudit-Sis.Admins.esstu"
APP_VERSION = "2.0"
AUDIT_DATE = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
TEAM_NAME = "Sis.Admins.esstu"
TEAM_MEMBERS = [
    "Сандакова Ирина (капитан) - К65.01",
    "Сараев Данила - К65.01",
    "Перфильев Денис - К65.02",
    "Большаков Олег - Б733-1",
    "Савин Степан - Б733-2"
]

class Colors:
    HEADER = Fore.MAGENTA + Style.BRIGHT
    INFO = Fore.CYAN
    SUCCESS = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    ERROR = Fore.RED + Style.BRIGHT
    CRITICAL = Back.RED + Fore.WHITE + Style.BRIGHT
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

class VulnerabilityDB:
    DANGEROUS_PORTS = {
        21: {'service': 'FTP', 'risk': 'HIGH', 'description': 'FTP передает данные в открытом виде', 'remediation': 'sudo apt purge vsftpd || sudo systemctl stop vsftpd'},
        23: {'service': 'Telnet', 'risk': 'CRITICAL', 'description': 'Telnet не шифрует трафик', 'remediation': 'sudo systemctl stop telnet && sudo systemctl disable telnet'},
        25: {'service': 'SMTP', 'risk': 'MEDIUM', 'description': 'Открытый SMTP релей', 'remediation': 'Настроить аутентификацию'},
        513: {'service': 'Rlogin', 'risk': 'CRITICAL', 'description': 'Устаревший протокол', 'remediation': 'sudo systemctl disable rlogin'},
        514: {'service': 'Rsh', 'risk': 'CRITICAL', 'description': 'Устаревший протокол', 'remediation': 'sudo systemctl disable rsh'},
        3306: {'service': 'MySQL', 'risk': 'MEDIUM', 'description': 'База данных доступна извне', 'remediation': 'sudo ufw deny 3306'},
        5432: {'service': 'PostgreSQL', 'risk': 'MEDIUM', 'description': 'База данных доступна извне', 'remediation': 'sudo ufw deny 5432'},
        6379: {'service': 'Redis', 'risk': 'HIGH', 'description': 'Redis без пароля', 'remediation': 'Установить пароль в redis.conf'},
        27017: {'service': 'MongoDB', 'risk': 'HIGH', 'description': 'MongoDB без аутентификации', 'remediation': 'Включить аутентификацию'}
    }
    
    SENSITIVE_FILES = [
        '/etc/shadow', '/etc/passwd', '/etc/sudoers', '/etc/ssh/sshd_config',
        '/etc/crontab', '/var/log/auth.log', '~/.bash_history',
        '~/.ssh/id_rsa', '~/.ssh/id_dsa', '~/.ssh/authorized_keys',
        '~/.aws/credentials', '~/.docker/config.json'
    ]
    
    VULNERABLE_VERSIONS = {
        'openssh': {'max': '8.4', 'risk': 'HIGH', 'cves': ['CVE-2021-28041']},
        'openssl': {'max': '1.1.1h', 'risk': 'CRITICAL', 'cves': ['CVE-2021-3449']},
        'sudo': {'max': '1.9.5p1', 'risk': 'CRITICAL', 'cves': ['CVE-2021-3156']}
    }

class SecurityAuditor:
    def __init__(self, verbose=False, output_format='table', report_file=None):
        self.verbose = verbose
        self.output_format = output_format
        self.report_file = report_file
        self.system_info = self.get_system_info()
        self.current_user = os.getenv('USER') or 'unknown'
        self.is_root = os.geteuid() == 0
        
    def get_system_info(self) -> Dict:
        info = {'hostname': socket.gethostname(), 'os': 'Unknown', 'kernel': 'Unknown'}
        try:
            with open('/etc/os-release') as f:
                match = re.search(r'PRETTY_NAME="(.+)"', f.read())
                if match:
                    info['os'] = match.group(1)
        except:
            pass
        try:
            info['kernel'] = os.uname().release
        except:
            pass
        return info
    
    def print_banner(self):
        banner = f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════════╗
║        ITBur-CyberAudit - Sis.Admins.esstu                        ║
║              Automated Security Auditor for Linux                 ║
║                         Version {APP_VERSION}                                  ║
╚════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.INFO}Team:{Colors.RESET} {TEAM_NAME}
{Colors.INFO}Captain:{Colors.RESET} Сандакова Ирина (К65.01)
{Colors.INFO}Members:{Colors.RESET} Сараев Д., Перфильев Д., Большаков О., Савин С.

{Colors.BOLD}System:{Colors.RESET} {self.system_info['hostname']} | {self.system_info['os']} | {self.system_info['kernel']}
{Colors.BOLD}User:{Colors.RESET} {self.current_user} {'(ROOT)' if self.is_root else '(limited)'}
{Colors.BOLD}Date:{Colors.RESET} {AUDIT_DATE}

{'⚠️  Limited privileges - some checks may be incomplete' if not self.is_root else '✅ Root privileges - full audit possible'}
{Colors.BOLD}Starting audit...{Colors.RESET}
"""
        print(banner)
    
    def run_command(self, command: str) -> Tuple[str, str, int]:
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=30)
            return stdout.strip(), stderr.strip(), process.returncode
        except:
            return "", "Error", -1
    
    def check_file_permissions(self) -> List[Dict]:
        print(f"{Colors.INFO}[*] Checking file permissions...{Colors.RESET}")
        findings = []
        
        for directory in ['/etc', '/var', '/home', '/root', '/tmp']:
            if not os.path.exists(directory):
                continue
            stdout, _, _ = self.run_command(f"find {directory} -type f -perm -0002 2>/dev/null | head -20")
            for file_path in stdout.split('\n'):
                if not file_path or not file_path.strip() or os.path.islink(file_path):
                    continue
                try:
                    stat = os.stat(file_path)
                    perms = oct(stat.st_mode)[-3:]
                    if perms in ['777', '666']:
                        findings.append({
                            'type': 'dangerous_permissions', 'file': file_path, 'permissions': perms,
                            'risk': 'HIGH' if perms == '777' else 'MEDIUM',
                            'description': f'Опасные права доступа {perms}',
                            'remediation': f'sudo chmod 644 {file_path}'
                        })
                except:
                    continue
        
        for pattern in VulnerabilityDB.SENSITIVE_FILES:
            file_path = pattern.replace('~', os.path.expanduser('~'))
            if os.path.exists(file_path):
                try:
                    stat = os.stat(file_path)
                    perms = oct(stat.st_mode)[-3:]
                    if 'shadow' in file_path and (stat.st_mode & 0o004 or stat.st_mode & 0o002):
                        findings.append({
                            'type': 'sensitive_file_exposure', 'file': file_path, 'permissions': perms,
                            'risk': 'CRITICAL', 'description': 'Файл shadow доступен всем!',
                            'remediation': 'sudo chmod 640 /etc/shadow'
                        })
                    elif 'id_rsa' in file_path and perms not in ['600', '400']:
                        findings.append({
                            'type': 'sensitive_file_exposure', 'file': file_path, 'permissions': perms,
                            'risk': 'CRITICAL', 'description': 'Приватный SSH ключ с неправильными правами',
                            'remediation': f'chmod 600 {file_path}'
                        })
                except:
                    continue
        return findings
    
    def check_network_services(self) -> List[Dict]:
        print(f"{Colors.INFO}[*] Scanning network services...{Colors.RESET}")
        findings = []
        stdout, _, _ = self.run_command("ss -tulpn | grep LISTEN")
        if not stdout:
            stdout, _, _ = self.run_command("netstat -tulpn | grep LISTEN")
        
        for line in stdout.split('\n'):
            match = re.search(r':(\d+)', line)
            if match:
                port = int(match.group(1))
                if port in VulnerabilityDB.DANGEROUS_PORTS:
                    info = VulnerabilityDB.DANGEROUS_PORTS[port]
                    findings.append({
                        'type': 'dangerous_port', 'port': port, 'service': info['service'],
                        'risk': info['risk'], 'description': info['description'],
                        'remediation': info['remediation']
                    })
        
        if self.run_command("echo 'quit' | ftp localhost 2>/dev/null | grep '230'")[0]:
            findings.append({
                'type': 'anonymous_ftp', 'service': 'FTP', 'risk': 'HIGH',
                'description': 'Анонимный FTP доступ', 'remediation': 'Отключить анонимный вход'
            })
        return findings
    
    def check_package_versions(self) -> List[Dict]:
        print(f"{Colors.INFO}[*] Checking package versions...{Colors.RESET}")
        findings = []
        stdout, _, _ = self.run_command("dpkg -l | grep '^ii'")
        
        for line in stdout.split('\n'):
            for pkg, info in VulnerabilityDB.VULNERABLE_VERSIONS.items():
                if pkg in line.lower():
                    match = re.search(r'(\d+\.\d+\.?\d*)', line)
                    if match and match.group(1) <= info['max']:
                        findings.append({
                            'type': 'vulnerable_package', 'package': pkg,
                            'installed_version': match.group(1), 'risk': info['risk'],
                            'description': f'Уязвимая версия {pkg}',
                            'remediation': f'sudo apt update && sudo apt upgrade {pkg}',
                            'cves': info['cves']
                        })
        return findings
    
    def check_system_components(self) -> List[Dict]:
        print(f"{Colors.INFO}[*] Checking system components...{Colors.RESET}")
        findings = []
        
        if os.path.exists('/etc/login.defs'):
            with open('/etc/login.defs') as f:
                match = re.search(r'PASS_MIN_LEN\s+(\d+)', f.read())
                if match and int(match.group(1)) < 8:
                    findings.append({
                        'type': 'weak_password_policy', 'component': 'password_policy',
                        'risk': 'MEDIUM', 'description': 'Минимальная длина пароля < 8',
                        'remediation': 'Установите PASS_MIN_LEN 8'
                    })
        
        stdout, _, _ = self.run_command("cat /etc/crontab 2>/dev/null")
        for pattern in ['wget', 'curl', 'nc -e', 'bash -i']:
            if pattern in stdout:
                findings.append({
                    'type': 'suspicious_cron', 'component': 'cron', 'risk': 'HIGH',
                    'description': f'Подозрительная cron задача с {pattern}',
                    'remediation': 'Проверьте /etc/crontab'
                })
                break
        
        if self.run_command("sudo -l 2>/dev/null | grep 'NOPASSWD'")[0]:
            findings.append({
                'type': 'insecure_sudoers', 'component': 'sudo', 'risk': 'HIGH',
                'description': 'NOPASSWD в sudoers', 'remediation': 'Удалите NOPASSWD'
            })
        return findings
    
    def check_database_configs(self) -> List[Dict]:
        print(f"{Colors.INFO}[*] Checking database configs...{Colors.RESET}")
        findings = []
        
        if self.run_command("mysql -u root -e 'SELECT User FROM mysql.user' 2>/dev/null")[0]:
            findings.append({
                'type': 'mysql_no_password', 'database': 'MySQL', 'risk': 'CRITICAL',
                'description': 'MySQL доступен без пароля',
                'remediation': 'mysql_secure_installation'
            })
        
        pg_out, pg_err, _ = self.run_command("sudo -u postgres psql -c 'SELECT 1' 2>/dev/null")
        if pg_err == '' and pg_out:
            findings.append({
                'type': 'postgres_no_auth', 'database': 'PostgreSQL', 'risk': 'HIGH',
                'description': 'PostgreSQL доступен без пароля',
                'remediation': 'Настройте pg_hba.conf'
            })
        return findings
    
    def check_suid_sgid(self) -> List[Dict]:
        print(f"{Colors.INFO}[*] Checking SUID/SGID binaries...{Colors.RESET}")
        findings = []
        stdout, _, _ = self.run_command("find / -type f -perm -4000 -o -perm -2000 2>/dev/null | head -50")
        dangerous = ['nmap', 'vim', 'find', 'bash', 'sh', 'cp', 'mv']
        
        for binary in stdout.split('\n'):
            if binary and os.path.basename(binary) in dangerous:
                findings.append({
                    'type': 'dangerous_suid', 'file': binary, 'risk': 'HIGH',
                    'description': f'Опасный SUID бит на {os.path.basename(binary)}',
                    'remediation': f'sudo chmod u-s {binary}'
                })
        return findings
    
    def generate_report(self, all_findings: Dict):
        total = sum(len(f) for f in all_findings.values())
        
        if self.output_format == 'json':
            report = {
                'metadata': {'team': TEAM_NAME, 'date': AUDIT_DATE, 'total': total},
                'findings': all_findings
            }
            if self.report_file:
                with open(self.report_file, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"\n{Colors.SUCCESS}✓ Report saved to {self.report_file}")
            else:
                print(json.dumps(report, indent=2))
        else:
            print(f"\n{Colors.HEADER}{'='*60}")
            print(f"SECURITY AUDIT REPORT - {TEAM_NAME}")
            print(f"{'='*60}{Colors.RESET}\n")
            print(f"Total vulnerabilities: {Colors.ERROR if total else Colors.SUCCESS}{total}{Colors.RESET}\n")
            
            for category, findings in all_findings.items():
                if findings:
                    print(f"{Colors.BOLD}{category.replace('_', ' ').upper()}:")
                    for f in findings:
                        color = Colors.CRITICAL if f['risk'] == 'CRITICAL' else Colors.ERROR if f['risk'] == 'HIGH' else Colors.WARNING
                        print(f"\n  {color}[{f['risk']}]{Colors.RESET} {f['description']}")
                        if 'file' in f:
                            print(f"    File: {f['file']}")
                        if 'port' in f:
                            print(f"    Port: {f['port']} ({f.get('service', '')})")
                        if 'package' in f:
                            print(f"    Package: {f['package']} {f.get('installed_version', '')}")
                        if 'cves' in f:
                            print(f"    CVEs: {', '.join(f['cves'])}")
                        print(f"    {Colors.WARNING}→ Fix:{Colors.RESET} {f['remediation']}")
                    print()
        
        if total:
            print(f"\n{Colors.ERROR}⚠ Found {total} issues requiring attention!")
        else:
            print(f"\n{Colors.SUCCESS}✓ No issues found - system is secure!")
    
    def run_full_audit(self):
        self.print_banner()
        all_findings = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self.check_file_permissions): 'file_permissions',
                executor.submit(self.check_network_services): 'network_services',
                executor.submit(self.check_package_versions): 'package_versions',
                executor.submit(self.check_system_components): 'system_components',
                executor.submit(self.check_database_configs): 'database_configs',
                executor.submit(self.check_suid_sgid): 'suid_sgid'
            }
            for future in concurrent.futures.as_completed(futures):
                all_findings[futures[future]] = future.result()
        
        self.generate_report(all_findings)
        return all_findings

def main():
    parser = argparse.ArgumentParser(description='ITBur-CyberAudit Security Auditor')
    parser.add_argument('--full', action='store_true', help='Run full audit')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--output', '-o', choices=['table', 'json'], default='table', help='Output format')
    parser.add_argument('--report', '-r', type=str, help='Save report to file')
    
    args = parser.parse_args()
    
    if not args.full:
        parser.print_help()
        return
    
    auditor = SecurityAuditor(args.verbose, args.output, args.report)
    auditor.run_full_audit()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}⚠ Audit interrupted")
    except Exception as e:
        print(f"\n{Colors.ERROR}✗ Error: {e}")