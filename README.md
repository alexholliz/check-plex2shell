# check-plex2shell

Read-only checks for signs of compromise from the Plex2Shell vulnerability
chain (CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, and
CVE-2026-96656).

Plex Media Server versions before `1.43.3.10861` are vulnerable. This script
checks the installed version and looks for known process, file, network, and
log indicators. A clean result cannot prove that a previously vulnerable
server was never compromised.

## Unraid with `plexinc/pms-docker:latest`

Run the checker from the Unraid host, not from inside the Plex container.

The `plexinc/pms-docker:latest` image does not include the `ss` command by
default. Before running the checker, open the Plex container console from the
Unraid web interface and install `iproute2`:

```sh
apt update && apt install -y iproute2
```

Exit the container console, copy `check-plex2shell.sh` to the Unraid host, and
run:

```sh
bash check-plex2shell.sh
```

Installing `iproute2` this way changes only the running container. The package
will normally need to be installed again after the container is recreated or
updated. If `ss` is unavailable inside the container, the script attempts a
host-side check using `nsenter` and `ss`; otherwise, it reports the network
check as skipped and returns an incomplete result.

## Results

- `PASS`: the installed version is patched and all available checks passed.
- `INCOMPLETE` or `UNKNOWN`: one or more checks could not be completed.
- `FAIL`: a vulnerable version or known compromise indicator was found.

If the server was reachable from the internet while running a version older
than `1.43.3.10861`, treat it as potentially compromised even if this script
finds no current indicators.

## Attribution

Based on the original
[Plex2Shell checker by gmolveau](https://gist.github.com/gmolveau/b02c2e58b877cf138e2859dbfb5cc20e),
with fixes for Docker container detection, version parsing, incomplete results,
and Unraid compatibility.
