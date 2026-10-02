# Ansible Role: AdGuard Home

![GitHub Workflow Status](https://img.shields.io/github/workflow/status/kitos9112/ansible-adguardhome/CI?style=flat) ![GitHub](https://img.shields.io/github/license/kitos9112/ansible-adguardhome?style=flat) [![Ansible Galaxy](https://img.shields.io/badge/galaxy-kitos9112.adguardhome-660198?style=flat)](https://galaxy.ansible.com/kitos9112/adguardhome) ![Ansible Quality Score](https://img.shields.io/ansible/quality/46001?style=flat)

Install [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) privacy
protecting and ad-blocking DNS server with Ansible.

## Requirements

- Ansible >= 2.12 (might work on previous versions)

## Supported Operating Systems

Tested on:

- Ubuntu 20.04 and 22.04
- Recent Fedora

It will likely work on other Debian and RHEL derived distros and versions than
what's listed above.

## Role Variables

Configurable role variables are all defined in `defaults/main.yml`:

```yaml
# Version of AdGuard Home to install (without "v" prefix). If set to "latest",
# lookup the latest release via GitHub API.
adguardhome_version: "latest"

# When desired version is "latest", use GITHUB_TOKEN environment variable when
# looking up the latest release via GitHub's API. If you get rate limit errors
# from GitHub's API, turn this on and set the GITHUB_TOKEN environment variable
# to a Personal Access Token with "repo" and "user" scopes.
adguardhome_use_github_token: false

# User to run AdGuard Home under. Must initially be "root" if no config file is
# on disk. After going through the setup wizard, or manually adding a config
# file, this can be set to something else, like "adguard" for example.
adguardhome_user: root
adguardhome_group: "{{ adguardhome_user }}"

# When setting adguardhome_user to something other than "root", this determines
# if the user will be created as a system user or not. Rule of thumb is if the
# user is logged in to by humans, it probably is not a system user.
adguardhome_system_user: true

# Default paths.
adguardhome_bin_dir: "/opt/{{ adguardhome_service_name }}/bin"
adguardhome_config_dir: "/opt/{{ adguardhome_service_name }}/config"
adguardhome_config_name: AdGuardHome.yml
adguardhome_data_dir: "/opt/{{ adguardhome_service_name }}"
adguardhome_tmp_dir: /tmp

# Enable and start systemd service unit?
adguardhome_service_name: "adguardhome"
adguardhome_service_enable: true
adguardhome_service_start: true

# Disable DNSStubResolver if systemd-resolved servicee is running.
adguardhome_disable_systemd_dnsstubresolver: true
```

## Example Playbook

The following example will install the latest available release of AdGuard Home:

```yaml
- hosts: all
  roles:
    - { role: kitos9112.adguardhome }
```

If you did not already have a configuration file in place, AdGuard Home will now
be running with it's setup wizard on port `3000`. Once you've gone through the
setup wizard, the admin interface should be accessible on ports `80` and `443`.

### Non-root User

You can run AdGuard Home as a non-root user once you have a config file for in
place. Without a config file, it will simply refuse to start if not running as
`root`.

If you don't already have a config file from a different install of AdGuard
Home, the best approach is:

1. Run the role with `adguardhome_user` set to `root`.
2. Go through the setup wizard available on port `3000`.
3. Run the role again, this time setting `adguardhome_user` to a non-root
   user. If the specified user does not exist, it will be created.

Personally I run AdGuard Home under a user called `adguard`.

### Read-only adoption of an existing installation

Set `adguardhome_adopt_existing: true` to validate an already-installed,
already-active service without applying the role's normal install or
configuration tasks. This mode requires an explicit pinned
`adguardhome_version` in `major.minor.patch` form, plus an existing executable,
configuration file, systemd unit, and active service. It checks the installed
binary version and validates a private temporary copy of the configuration
with AdGuard Home's `--check-config` option. The candidate and its working
directory are isolated from the live config and data paths and removed after
validation, including when validation fails. This protects the live file from
schema migration performed by `--check-config`. Adoption does not modify the
live configuration, unit, binary, service state, capabilities, DNS
integration, or runtime data such as DHCP leases. The default is `false`.

This mode is only a read-only adoption check. It does not implement desired
configuration management, create backups, or provide recovery. Review and
validate those separately before enabling normal configuration tasks.

### Managing configuration on an existing installation

Set `adguardhome_manage_existing: true` and provide the complete desired YAML
as `adguardhome_desired_config` from a protected variable source. This mode
requires the same pinned, existing, active installation as read-only adoption.
It changes only the AdGuard Home configuration file: it validates private
staging copies, compares YAML semantically while retaining runtime filter
`last_updated` values, and does not restart or rewrite the live file when the
desired configuration is already equivalent. A changed configuration is
installed atomically with the existing file's owner, group, and mode, then the
service is restarted once and checked for active state and a successful DNS A
answer through the configured local listener. The DNS check defaults to
`127.0.0.1:53` for `example.com` and has a bounded timeout.

If activation or health validation fails, the role restores the exact prior
configuration bytes and attempts one compensating restart, then checks service
and DNS health. The temporary rollback copy is private and removed at task
completion. This is a bounded configuration rollback mechanism, not a claim
that host recovery has been tested; synthetic tests exercise the transaction
and compensation branches. It does not manage the binary, unit, account,
capabilities, DNS integration, or runtime data such as DHCP leases. The default
is disabled.

## License

This project is licensed under the MIT License.

## Author Information

[Marcos Soutullo](https://github.com/kitos9112)
