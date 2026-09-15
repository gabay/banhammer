# Banhammer

A single-binary, low-footprint intrusion-prevention daemon — `fail2ban` without the Python
runtime or the `.conf`/`.local` inheritance maze.

Tail logs (text or JSON) from files or sockets, match offending lines, extract the offender's IP,
and ban it with `iptables`/`nft`/`ipset`/any command when it shows up **X times in Y minutes** —
then unban it **Z minutes** later.

```yaml
monitors:
  sshd:
    file: /var/log/auth.log
    match: "Failed password .* from <IP>"
```
> 5 hits in 10 minutes ⇒ `DROP` for 1 hour. That's the whole config.

**Status: design phase.** No code yet — see [PROJECT.md](./PROJECT.md) for the architecture and
implementation plan, and [config.example.yaml](./config.example.yaml) for the config surface.
