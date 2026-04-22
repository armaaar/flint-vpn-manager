---
name: Bug report
about: Something doesn't work on the supported configuration
title: "[Bug] "
labels: bug
---

## Configuration

- **Router model**: (should be GL.iNet Flint 2 / GL-MT6000)
- **Router firmware version**: (exact version, e.g. 4.8.4)
- **Host OS**: (e.g. Ubuntu 24.04)
- **Python version**: (`python --version`)
- **Node version**: (`node --version`)
- **Flint VPN Manager commit**: (`git rev-parse HEAD`)

> If you're running on a different router, firmware, or VPN provider, please note that the project is not supported there. You're welcome to file an issue but it may be closed as out-of-scope.

## What happened

A clear description of the behaviour you observed.

## What you expected

A clear description of what you expected to happen.

## Repro steps

1.
2.
3.

## Logs

Relevant excerpts from:

- `logs/app.log`
- `logs/error.log` (stack traces are especially helpful)
- `logs/access.log` (if it looks like an HTTP-level issue)

```
paste logs here
```

## Router state (if routing-related)

```
# Run on the router and paste relevant output:
uci show route_policy
wg show
ipset list | head -60
```

## Additional context

Screenshots, network topology, anything else that might help.
