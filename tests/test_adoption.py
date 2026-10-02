"""Synthetic tests for the read-only existing-installation adoption path."""

import hashlib
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import threading

import pytest
import yaml


SOURCE = Path(__file__).resolve().parents[1]
VERSION = "0.107.71"
CANARY = "ADGUARD_SYNTHETIC_CONFIG_CANARY_0c55"
MANAGED_CONFIG = f"""http:
  address: 0.0.0.0:80
upstream_dns:
  - https://example.invalid/dns?token={CANARY}
filters:
  - enabled: true
    url: https://example.invalid/filter.txt
    name: Managed filter
    id: 1
"""
RUNNING_CONFIG = f"""# Runtime formatting and timestamps are not desired state.
filters:
    - last_updated: '2025-01-02T03:04:05Z'
      id: 1
      name: Managed filter
      enabled: true
      url: https://example.invalid/filter.txt
upstream_dns: [https://example.invalid/dns?token={CANARY}]
http: {{address: 0.0.0.0:80}}
"""


class FakeDnsServer:
    """Answer a local DNS question with a synthetic A record."""

    def __init__(self, failure="none"):
        self.failure = failure
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stopped.is_set():
            try:
                query, peer = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(query) < 17:
                continue
            qname_end = 12
            while qname_end < len(query) and query[qname_end] != 0:
                qname_end += 1 + query[qname_end]
            question_end = qname_end + 5
            if question_end > len(query):
                continue
            question = query[12:question_end]
            ident = query[:2]
            flags = 0x8180
            answers = 1
            if self.failure == "wrong-id":
                next_id = (int.from_bytes(ident, "big") + 1) % 65536
                ident = struct.pack("!H", next_id)
            elif self.failure == "nxdomain":
                flags = 0x8183
                answers = 0
            elif self.failure == "no-answer":
                answers = 0
            counts = struct.pack("!HHHH", 1, answers, 0, 0)
            response = ident + struct.pack("!H", flags) + counts + question
            if answers:
                response += (
                    b"\xc0\x0c"
                    + struct.pack("!HHIH", 1, 1, 30, 4)
                    + bytes((93, 184, 216, 34))
                )
            self.sock.sendto(response, peer)

    def close(self):
        self.stopped.set()
        self.sock.close()
        self.thread.join(timeout=1)


def _snapshot(paths):
    return {
        str(path): (
            path.stat().st_mode & 0o777,
            path.stat().st_uid,
            path.stat().st_gid,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in paths
        if path.exists()
    }


def _fixture(
    tmp_path,
    *,
    version=VERSION,
    binary_version=VERSION,
    config_text="dhcp:\n  port: 67\n",
    active=True,
    missing=None,
    config_symlink=False,
    manage_existing=False,
    desired_config="",
    restart_failure="none",
    health_failure=False,
    dns_failure="none",
):
    roles = tmp_path / "roles"
    roles.mkdir()
    shutil.copytree(
        SOURCE, roles / "adguardhome", ignore=shutil.ignore_patterns(".git")
    )

    root = tmp_path / "existing"
    dns_server = FakeDnsServer(dns_failure)
    binary_dir = root / "bin"
    config_dir = root / "config"
    work_dir = root / "work"
    for directory in (binary_dir, config_dir, work_dir / "data"):
        directory.mkdir(parents=True, exist_ok=True)
    binary = binary_dir / "AdGuardHome"
    config = config_dir / "AdGuardHome.yml"
    unit = root / "adguardhome.service"
    lease_db = work_dir / "data" / "leases.db"
    runtime_state = work_dir / "data" / "sessions.db"

    binary.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--version\" ]; then\n"
        f"  printf '%s\\n' 'AdGuard Home, version v{binary_version}'\n"
        "  exit 0\n"
        "fi\n"
        "config=\"\"\n"
        "work_dir=\"\"\n"
        "while [ $# -gt 0 ]; do\n"
        "  if [ \"$1\" = \"-c\" ] || [ \"$1\" = \"--config\" ]; then "
        "shift; config=\"$1\"; fi\n"
        "  if [ \"$1\" = \"--work-dir\" ]; then "
        "shift; work_dir=\"$1\"; fi\n"
        "  shift\n"
        "done\n"
        "printf '%s\\n%s\\n%s\\n%s\\n%s\\n' \"$config\" "
        "\"$work_dir\" \"$PWD\" \"$(ls -ld \"$config\" | cut -c1-10)\" "
        "\"$(ls -ld \"$work_dir\" | cut -c1-10)\" "
        ">> \"$ADGUARD_TEST_CHECK_LOG\"\n"
        "cat \"$config\" >/dev/null\n"
        "printf '%s\\n' '# MUTATED_CANDIDATE_ONLY' >> \"$config\"\n"
        f"printf '%s\\n' '{CANARY}'\n"
        "grep -q '^invalid' \"$config\" && exit 2\n"
        "exit 0\n"
    )
    binary.chmod(0o750)
    config.write_text(config_text)
    config_target = config
    if config_symlink:
        config_target = config_dir / "AdGuardHome.source.yml"
        config.rename(config_target)
        config.symlink_to(config_target.name)
    unit.write_text("[Unit]\nDescription=Synthetic AdGuard\n")
    lease_db.write_text("synthetic DHCP lease state\n")
    runtime_state.write_text("synthetic runtime state\n")
    if missing == "binary":
        binary.unlink()
    elif missing == "config":
        config.unlink()
    elif missing == "unit":
        unit.unlink()

    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    systemctl_log = tmp_path / "systemctl.log"
    check_log = tmp_path / "check-config.log"
    systemctl = fakebin / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$ADGUARD_TEST_SYSTEMCTL_LOG\"\n"
        "if [ \"$1\" = \"is-active\" ]; then\n"
        "  restarts=$(grep -c '^restart ' \"$ADGUARD_TEST_SYSTEMCTL_LOG\" "
        "|| true)\n"
        "  if [ \"$restarts\" -gt 0 ] && "
        "[ \"$ADGUARD_TEST_HEALTH_FAILURE\" = true ]; then exit 3; fi\n"
        "  [ \"$ADGUARD_TEST_SERVICE_ACTIVE\" = true ] && exit 0\n"
        "  exit 3\n"
        "fi\n"
        "if [ \"$1\" = \"restart\" ]; then\n"
        "  restarts=$(grep -c '^restart ' \"$ADGUARD_TEST_SYSTEMCTL_LOG\")\n"
        "  [ \"$ADGUARD_TEST_RESTART_FAILURE\" = all ] && exit 1\n"
        "  [ \"$ADGUARD_TEST_RESTART_FAILURE\" = first ] && "
        "[ \"$restarts\" -eq 1 ] && exit 1\n"
        "fi\n"
        "exit 0\n"
    )
    systemctl.chmod(0o750)

    variables = {
        "adguardhome_adopt_existing": not manage_existing,
        "adguardhome_manage_existing": manage_existing,
        "adguardhome_desired_config": desired_config,
        "adguardhome_manage_dns_health_address": "127.0.0.1",
        "adguardhome_manage_dns_health_port": dns_server.port,
        "adguardhome_manage_dns_health_timeout": 0.3,
        "adguardhome_bin_dir": str(binary_dir),
        "adguardhome_config_dir": str(config_dir),
        "adguardhome_data_dir": str(work_dir),
        "adguardhome_service_name": "adguardhome",
        "adguardhome_service_unit_file": str(unit),
    }
    if version is not None:
        variables["adguardhome_version"] = version
    playbook = tmp_path / "play.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Synthetic read-only adoption",
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "become": False,
                    "vars": variables,
                    "roles": ["adguardhome"],
                }
            ],
            sort_keys=False,
        )
    )
    config_file = tmp_path / "ansible.cfg"
    config_file.write_text(
        "[defaults]\n"
        f"roles_path = {roles}\n"
        f"local_tmp = {tmp_path / 'ansible-tmp'}\n"
        "retry_files_enabled = False\n"
        "host_key_checking = True\n"
    )
    home = tmp_path / "home"
    home.mkdir()
    env = {
        "PATH": (
            str(fakebin)
            + os.pathsep
            + str(Path(sys.executable).parent)
            + os.pathsep
            + os.defpath
        ),
        "HOME": str(home),
        "ANSIBLE_HOME": str(home / "ansible"),
        "ANSIBLE_CONFIG": str(config_file),
        "ANSIBLE_NOCOLOR": "1",
        "LANG": "C.UTF-8",
        "ADGUARD_TEST_SYSTEMCTL_LOG": str(systemctl_log),
        "ADGUARD_TEST_CHECK_LOG": str(check_log),
        "ADGUARD_TEST_SERVICE_ACTIVE": "true" if active else "false",
        "ADGUARD_TEST_RESTART_FAILURE": restart_failure,
        "ADGUARD_TEST_HEALTH_FAILURE": "true" if health_failure else "false",
    }
    command = [
        sys.executable,
        "-m",
        "ansible.cli.playbook",
        "-vvv",
        "-i",
        "localhost,",
        str(playbook),
    ]
    protected_paths = [
        binary, config_target, config, unit, lease_db, runtime_state
    ]
    return (
        command, env, systemctl_log, check_log, protected_paths, config,
        dns_server,
    )


def _run(tmp_path, **fixture_args):
    (
        command, env, systemctl_log, check_log, protected_paths, config,
        dns_server,
    ) = _fixture(tmp_path, **fixture_args)
    before = _snapshot(protected_paths)
    try:
        result = subprocess.run(
            command,
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        dns_server.close()
    after = _snapshot(protected_paths)
    return result, before, after, systemctl_log, check_log, config


def test_adoption_is_read_only_and_validates_existing_native_install(
    tmp_path,
):
    result, before, after, systemctl_log, check_log, config = _run(tmp_path)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "changed=0" in output, output
    assert before == after
    assert systemctl_log.read_text().splitlines() == [
        "is-active --quiet adguardhome.service"
    ]
    assert CANARY not in output
    checked_config, work_dir, command_cwd, candidate_mode, directory_mode = (
        check_log.read_text().splitlines()
    )
    assert checked_config != str(config)
    assert Path(checked_config).parent == Path(work_dir) == Path(command_cwd)
    assert candidate_mode == "-rw-------"
    assert directory_mode == "drwx------"
    assert not Path(work_dir).exists()


@pytest.mark.parametrize("version", [None, "latest", "development"])
def test_unpinned_or_invalid_version_fails_without_touching_existing_state(
    tmp_path, version
):
    result, before, after, systemctl_log, _, _ = _run(
        tmp_path, version=version)
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "requires an explicit pinned version" in output
    assert before == after
    assert not systemctl_log.exists()
    assert CANARY not in output


def test_invalid_config_fails_without_restarting_or_touching_runtime_state(
    tmp_path,
):
    result, before, after, systemctl_log, check_log, config = _run(
        tmp_path, config_text=f"invalid: {CANARY}\n"
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "existing configuration failed validation" in output
    assert before == after
    assert systemctl_log.read_text().splitlines() == [
        "is-active --quiet adguardhome.service"
    ]
    assert CANARY not in output
    checked_config, work_dir, command_cwd, candidate_mode, directory_mode = (
        check_log.read_text().splitlines()
    )
    assert checked_config != str(config)
    assert Path(checked_config).parent == Path(work_dir) == Path(command_cwd)
    assert candidate_mode == "-rw-------"
    assert directory_mode == "drwx------"
    assert not Path(work_dir).exists()


def test_mismatched_installed_version_fails_without_touching_existing_state(
    tmp_path,
):
    result, before, after, systemctl_log, _, _ = _run(
        tmp_path, binary_version="0.108.0"
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert (
        "existing AdGuard binary does not match adguardhome_version" in output
    )
    assert before == after
    assert systemctl_log.read_text().splitlines() == [
        "is-active --quiet adguardhome.service"
    ]
    assert CANARY not in output


@pytest.mark.parametrize("missing", ["binary", "config", "unit"])
def test_missing_existing_install_component_fails_without_modifications(
    tmp_path, missing
):
    result, before, after, systemctl_log, check_log, _ = _run(
        tmp_path, missing=missing)
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert (
        "existing executable binary, configuration file, and systemd unit"
        in output
    )
    assert before == after
    assert not systemctl_log.exists()
    assert not check_log.exists()
    assert CANARY not in output


def test_inactive_service_fails_without_restarting_or_recovering(tmp_path):
    result, before, after, systemctl_log, check_log, _ = _run(
        tmp_path, active=False)
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "existing AdGuard service to already be active" in output
    assert before == after
    assert systemctl_log.read_text().splitlines() == [
        "is-active --quiet adguardhome.service"
    ]
    assert CANARY not in output
    assert not check_log.exists()


def test_symlinked_live_config_is_rejected_before_validation(tmp_path):
    result, before, after, systemctl_log, check_log, config = _run(
        tmp_path, config_symlink=True)
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    message = (
        "existing executable binary, configuration file, and systemd unit"
    )
    assert message in output
    assert before == after
    assert config.is_symlink()
    assert not systemctl_log.exists()
    assert not check_log.exists()
    assert CANARY not in output


def test_legacy_secret_configuration_writes_are_private_and_suppressed():
    service_tasks = yaml.safe_load(
        (SOURCE / "tasks/systemd_service.yml").read_text()
    )
    config_task = next(
        task for task in service_tasks
        if task["name"] == "Apply configuration settings"
    )
    config_handler = next(
        task
        for task in yaml.safe_load(
            (SOURCE / "handlers/main.yml").read_text()
        )
        if task["name"] == "Apply AdGuard Home configuration"
    )
    for task in (config_task, config_handler):
        assert task["ansible.builtin.template"]["src"] == "adguardhome.yml.j2"
        assert task["ansible.builtin.template"]["mode"] == "0600"
        assert task["no_log"] is True
        assert task["diff"] is False


def test_legacy_handler_notification_names_remain_supported():
    handlers = yaml.safe_load((SOURCE / "handlers/main.yml").read_text())
    expected_aliases = {
        "Reload systemd daemon": "reload systemd daemon",
        "Restart AdGuard Home": "restart adguardhome",
        "Stop AdGuard Home": "stop adguardhome",
        "Apply AdGuard Home configuration": "apply adguardhome configuration",
        "Restart systemd-resolved": "restart systemd-resolved",
    }
    for handler in handlers:
        assert handler["listen"] == expected_aliases[handler["name"]]
    assert {handler["name"] for handler in handlers} == set(expected_aliases)


def _run_managed_fixture(tmp_path, **fixture_args):
    (
        command, env, systemctl_log, check_log, protected_paths, config,
        dns_server,
    ) = _fixture(tmp_path, manage_existing=True, **fixture_args)
    before = _snapshot(protected_paths)
    try:
        result = subprocess.run(
            command,
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        dns_server.close()
    after = _snapshot(protected_paths)
    return result, before, after, systemctl_log, check_log, config


def test_managed_semantic_noop_preserves_runtime_timestamp_and_state(tmp_path):
    result, before, after, systemctl_log, check_log, config = (
        _run_managed_fixture(tmp_path, config_text=RUNNING_CONFIG,
                             desired_config=MANAGED_CONFIG)
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "changed=0" in output, output
    assert before == after
    assert "last_updated: '2025-01-02T03:04:05Z'" in config.read_text()
    assert systemctl_log.read_text().splitlines() == [
        "is-active --quiet adguardhome.service"
    ]
    assert CANARY not in output
    for line in check_log.read_text().splitlines():
        assert str(config) not in line


def test_managed_change_validates_final_candidate_and_converges(tmp_path):
    result, before, after, systemctl_log, check_log, config = (
        _run_managed_fixture(
            tmp_path,
            config_text=RUNNING_CONFIG,
            desired_config=MANAGED_CONFIG.replace(
                "Managed filter", "Changed filter"
            ),
        )
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "changed=2" in output, output
    assert before != after
    assert before[str(config)][:3] == after[str(config)][:3]
    assert "Changed filter" in config.read_text()
    assert systemctl_log.read_text().splitlines() == [
        "is-active --quiet adguardhome.service",
        "restart adguardhome.service",
        "is-active --quiet adguardhome.service",
    ]
    checked_paths = check_log.read_text().splitlines()[::5]
    assert any(Path(path).name == "final.yml" for path in checked_paths)
    assert all(path != str(config) for path in checked_paths)
    assert CANARY not in output


@pytest.mark.parametrize("restart_failure,expected_restarts", [
    ("first", 2),
    ("all", 2),
])
def test_managed_restart_failure_restores_exact_config_once(
    tmp_path, restart_failure, expected_restarts
):
    result, before, after, systemctl_log, check_log, config = (
        _run_managed_fixture(
            tmp_path,
            config_text=RUNNING_CONFIG,
            desired_config=MANAGED_CONFIG.replace(
                "Managed filter", "Changed filter"
            ),
            restart_failure=restart_failure,
        )
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert (
        "Desired configuration failed health validation" in output
        if restart_failure == "first"
        else "Configuration activation and recovery failed" in output
    )
    assert before == after
    assert systemctl_log.read_text().splitlines().count(
        "restart adguardhome.service"
    ) == expected_restarts
    assert "last_updated: '2025-01-02T03:04:05Z'" in config.read_text()
    assert CANARY not in output
    checked_paths = [
        line.splitlines()[0] for line in check_log.read_text().splitlines()
    ]
    assert all(path != str(config) for path in checked_paths)


@pytest.mark.parametrize("dns_failure", ["wrong-id", "nxdomain", "no-answer"])
def test_managed_dns_health_failure_restores_config(tmp_path, dns_failure):
    result, before, after, systemctl_log, _, config = _run_managed_fixture(
        tmp_path,
        config_text=RUNNING_CONFIG,
        desired_config=MANAGED_CONFIG.replace(
            "Managed filter", "Changed filter"
        ),
        dns_failure=dns_failure,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "Configuration activation and recovery failed" in output
    assert before == after
    assert systemctl_log.read_text().splitlines().count(
        "restart adguardhome.service"
    ) == 2
    assert CANARY not in output


def test_invalid_managed_candidate_never_reaches_live_config(tmp_path):
    result, before, after, systemctl_log, check_log, config = (
        _run_managed_fixture(
            tmp_path,
            config_text=RUNNING_CONFIG,
            desired_config=f"invalid: {CANARY}\n",
        )
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "Desired configuration failed validation" in output
    assert before == after
    assert systemctl_log.read_text().splitlines() == [
        "is-active --quiet adguardhome.service"
    ]
    assert CANARY not in output
    assert all(
        str(config) not in line for line in check_log.read_text().splitlines()
    )
