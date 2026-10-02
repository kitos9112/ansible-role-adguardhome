"""Synthetic tests for the read-only existing-installation adoption path."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml


SOURCE = Path(__file__).resolve().parents[1]
VERSION = "0.107.71"
CANARY = "ADGUARD_SYNTHETIC_CONFIG_CANARY_0c55"


def _snapshot(paths):
    return {
        str(path): (
            path.stat().st_mode & 0o777,
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
):
    roles = tmp_path / "roles"
    roles.mkdir()
    shutil.copytree(
        SOURCE, roles / "adguardhome", ignore=shutil.ignore_patterns(".git")
    )

    root = tmp_path / "existing"
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
        "printf '%s\\n' 'MUTATED_CANDIDATE_ONLY' >> \"$config\"\n"
        f"printf '%s\\n' '{CANARY}'\n"
        "grep -q invalid \"$config\" && exit 2\n"
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
        "  [ \"$ADGUARD_TEST_SERVICE_ACTIVE\" = true ] && exit 0\n"
        "  exit 3\n"
        "fi\n"
        "exit 0\n"
    )
    systemctl.chmod(0o750)

    variables = {
        "adguardhome_adopt_existing": True,
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
    return command, env, systemctl_log, check_log, protected_paths, config


def _run(tmp_path, **fixture_args):
    command, env, systemctl_log, check_log, protected_paths, config = _fixture(
        tmp_path, **fixture_args
    )
    before = _snapshot(protected_paths)
    result = subprocess.run(
        command,
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
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
