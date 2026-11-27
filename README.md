# Home Network Agent

Reads AdGuard Home DNS query logs and asks an OpenAI model which domains to block, watch or unblock. You approve every change in the terminal.

## How it works

1. Fetches the query log incrementally (`querylog_window_days`), AdGuard user rules, and device names from the Asus router over SSH, in parallel.
2. Sends a compact summary to the model. Trusted, protected and reverted domains are never offered.
3. The model recommends blocks (subdomain, whole domain or wildcard), domains to watch, and unblocks for blocked domains a device keeps retrying.
4. You pick what to apply. Every AdGuard rule change is backed up to `rules_backup_dir` first.

## Setup

```bash
command -v uv || curl -LsSf https://astral.sh/uv/install.sh | sh   # install uv if missing
cp private.yaml.example private.yaml
uv sync
```

`config.yaml` is in git and holds the shared settings. `private.yaml` is not in git: it holds the AdGuard credentials, `openai_api_key` and personal domains. Copy it to every machine that runs the agent.
A list in `private.yaml` is added to the same list in `config.yaml`; any other key may be in only one file. Every key is required; a missing one fails at startup.
`router_ssh_host` must be an SSH alias (user, key, port) on the `router_ssh_jump` host, or locally when `router_ssh_jump` is `""`. The run fails if the router SSH fails.

### Router key (read-only)

Give the agent its own SSH key that the router limits to one read command, so a bug or a compromised host cannot change the router. On the jump host, create the key and an alias (here `router-agent`, set as `router_ssh_host`):

```bash
ssh-keygen -t ed25519 -N "" -C home-network-agent-readonly -f ~/.ssh/id_router_agent
```
```
Host router-agent
    HostName 192.168.50.1
    User admin
    IdentityFile ~/.ssh/id_router_agent
    IdentitiesOnly yes
```

In the router UI (Administration → System → Service → Authorized Keys) add a new line below your existing key. The command must match `COMMAND` in `router.py`:

```
command="cat /var/lib/misc/dnsmasq.leases; echo @@; nvram get custom_clientlist; echo @@; cat /proc/net/arp",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... home-network-agent-readonly
```

Check that any other command still only returns the client list: `ssh router-agent 'echo hacked'`.

## Usage

```bash
uv run agent.py                                      # analyze and review
uv run agent.py revert example.com "broke my service"
uv run agent.py revert 'abc*.example.com' "reason"   # quote wildcards
```

`revert` removes the block and records the reason; the domain is never suggested again. A host blocked only by a whole-domain or wildcard rule gets an allow rule instead.

## Test

```bash
uv run test_domain_coverage.py
```
