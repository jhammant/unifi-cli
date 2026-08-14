---
name: unifi
description: >-
  Read and change a UniFi network from the command line instead of clicking through the web UI.
  Use for anything network-related: Wi-Fi channels, SSIDs, WPA/PMF, roaming, VLANs, firewall
  rules, port forwards, DHCP/DNS, IPS, VPN, device firmware, client lists, or diagnosing
  "the wifi is slow / dropping / won't connect", and AirDrop / Universal Control / Sidecar
  problems. Triggers: unifi, udm, "my network", "the wifi", "the router", access point, AP,
  SSID, VLAN, port forward, firewall rule, channel, DFS, roaming, "what's connected".
---

# unifi — command-line control of a UniFi network

Do **not** drive the UniFi web UI with browser automation. Changing the 5 GHz channel on five
radios once took ~60 clicks; every one of those is a single command here. Only fall back to the
browser for the handful of things the API genuinely does not expose.

Tool lives at `unifi.py` in this repo.

## Setup

Config is read from `$UNIFI_ENV`, then `.env` beside the script, then
`~/.config/unifi-cli/.env`. Real environment variables always win.

```bash
UNIFI_HOST=192.168.1.1   # gateway address
UNIFI_SSH=udm            # ssh alias/host for reads
UNIFI_SITE=default       # site id — almost always "default"
UNIFI_USER=              # local admin, writes only
UNIFI_PASS=
```

Run `./unifi.py whoami` first — it reports which half of the tool is live.

## Two transports — pick deliberately

**Reads → Mongo over SSH.** Needs no credentials, works the moment you can SSH to the gateway,
and sees the *entire* controller database including settings the web UI never renders.

```bash
./unifi.py whoami           # connectivity + whether writes are available
./unifi.py radios           # every radio: channel, width, tx power, min-RSSI
./unifi.py wlans            # SSIDs: security, wpa mode, PMF, fast roaming
./unifi.py networks         # networks/VLANs/DHCP/DNS
./unifi.py forwards         # port forwards
./unifi.py devices          # models + firmware
./unifi.py settings ips     # one settings key (omit key for all)
./unifi.py collections      # what else is in there
./unifi.py read wlanconf --query '{name:"guest"}'
```

Secrets are redacted by default. `--raw` disables that — only use it when the secret is the
point, and never paste the output into a message or an artifact.

Note the curated views (`wlans`, `networks`, `forwards`) never select secret fields at all;
redaction matters most on `read` and `settings`, which return whole documents.

**Writes → the HTTPS API.** Requires a **local** admin. An SSO admin cannot authenticate an API
call, so if `whoami` says "reads only", that is usually why:

> UniFi → Settings → Admins & Users → Add Admin → tick **Restrict to Local Access Only**

```bash
./unifi.py api GET  /rest/wlanconf
./unifi.py api PUT  /rest/wlanconf/<id> '{"pmf_mode":"optional", ...}'
./unifi.py api POST /cmd/devmgr '{"mac":"...","cmd":"restart"}'
```

Paths not starting `/proxy/` or `/api/` get `/proxy/network/api/s/<site>` prefixed.

**Never write to Mongo directly.** The controller caches config in memory and will overwrite
you, or you desync the config version and have to restore from backup.

## Rules that have already bitten us

- **UniFi PUTs replace the whole object.** `GET` the record, modify the field, `PUT` the full
  document back. Sending only the changed key wipes everything else on that SSID or network.
- **Meshed APs share a 5 GHz channel with their parent.** Changing either changes both. Keep
  that pair **off DFS** or a radar hit takes the downstream AP offline.
- **AWDL is banned on DFS channels.** Apple peer-to-peer (Universal Control, AirDrop, Sidecar)
  breaks on any AP serving Macs if that AP sits on a DFS channel. Put the Mac-facing AP on
  **44** or **149** — both non-DFS *and* AWDL social channels, so the infra link and the AWDL
  link land on the same channel.
- **Check the regulatory domain.** In GB, non-DFS 5 GHz is **36–48** and **149–165**; 52–144 is
  DFS. At 80 MHz that is only *two* non-DFS blocks, so a house with many radios has to put some
  APs on DFS.
- **DFS costs a 1–10 min channel-availability check** before the radio transmits at all. A blank
  5 GHz column right after a change is normal, not a failure.
- **`radio_ai` can override pinned channels.** If its RF policy still has `dfs: true`, do not
  set any AP back to Auto.

## Diagnosing from the client side

The controller only tells half the story. For "it drops / it's slow", also check the client:

```bash
ipconfig getsummary en0                                                      # cached: channel, RSSI, no scan
/usr/bin/log show --last 1h --predicate 'process == "UniversalControl"' --style compact
/usr/bin/log show --last 1h --predicate 'process == "airportd"' --style compact | grep -ci roam
```

**Never poll `system_profiler SPAirPortDataType` in a loop.** It forces a 25-channel *active*
scan lasting ~20s, taking the radio off channel and starving AWDL/BLE — it causes the exact
dropout you are trying to observe. `ipconfig getsummary` reads cached state, no scan.
`uc-watch.sh` in this repo automates this correlation safely.

A client on the *wrong* AP looks like a channel problem but is not: check RSSI and PHY mode
before changing any radio. −65 dBm when a modern AP is in the same room means it is associated
to the wrong AP, not that the channel is bad.
