# NordVPN Wireguard Extractor & Config Generator

Turn your NordVPN subscription into a plain **WireGuard** configuration, for
any device that speaks WireGuard: the official WireGuard apps (Windows,
macOS, iOS, Android, Linux), **pfSense**, OPNsense, GL.iNet, OpenWrt and
other routers.

NordVPN's own apps use NordLynx, which is WireGuard underneath, but NordVPN
doesn't hand out ready-made WireGuard config files. This script fetches your
NordLynx private key with an access token, lets you pick a server, and
gives you everything a WireGuard client needs, as text, as a `.conf` file
and as a **QR code** in the terminal.

- One Python file, **standard library only**: nothing to `pip install`.
- Interactive: region → country → server, lowest load first.
- Shows the full config including your private key, and the public key
  that belongs to it.
- Writes a `.conf`, shows a QR code, or both.

> Not affiliated with NordVPN. It uses NordVPN's public server API and the
> credentials endpoint their manual-setup tokens are meant for.

---

## Contents

1. [What you need](#what-you-need)
2. [Download](#download)
3. [Get a NordVPN access token](#get-a-nordvpn-access-token)
4. [Run it](#run-it)
5. [What the script does, step by step](#what-the-script-does-step-by-step)
6. [Using the result: client examples](#using-the-result-client-examples)
   - [Phone (iOS / Android) with the QR code](#phone-ios--android-with-the-qr-code)
   - [Windows and macOS app](#windows-and-macos-app)
   - [Linux](#linux)
   - [pfSense](#pfsense)
   - [OPNsense](#opnsense)
   - [Other routers](#other-routers)
7. [Security notes](#security-notes)
8. [Limitations](#limitations)
9. [Troubleshooting](#troubleshooting)
10. [How it works](#how-it-works)

---

## What you need

| | Where to get it |
|---|---|
| An active **NordVPN subscription** | nordvpn.com |
| **Python 3.8 or newer** | see below |
| A **terminal** | Windows: PowerShell or Windows Terminal. macOS: Terminal. Linux: any terminal |
| A **WireGuard client** on the device you want to protect | [wireguard.com/install](https://www.wireguard.com/install/), or your router's WireGuard feature |

### Installing Python

**Windows**
- Download the installer from [python.org/downloads](https://www.python.org/downloads/).
  It includes the `py` launcher used below. Ticking *Add python.exe to
  PATH* is optional.
- Or from a terminal: `winget install Python.Python.3.12`
- Or from the Microsoft Store ("Python 3.12"). That version is started
  with `python`, not `py`.

Check it worked: `py -3 --version` (or `python --version`).

**macOS**
- Download the installer from [python.org/downloads](https://www.python.org/downloads/).
  **Afterwards run `Install Certificates.command`** in
  `/Applications/Python 3.x/`. Without it, HTTPS requests fail with
  `CERTIFICATE_VERIFY_FAILED`.
- Or with Homebrew: `brew install python`

Check it worked: `python3 --version`.

**Linux**: Python 3 is almost always preinstalled. If not:
`sudo apt install python3` (Debian/Ubuntu), `sudo dnf install python3`
(Fedora), `sudo pacman -S python` (Arch).

Nothing else is needed. The script uses only Python's standard library.

---

## Download

Pick one:

- **Git:** `git clone https://github.com/IdefixRC/NordVPN-Wireguard-Extractor-Config-Generator.git`
- **ZIP:** on the GitHub page, *Code* → *Download ZIP*, then unzip.
- **Just the script:** open `nord_wg_config.py` on GitHub → *Download raw
  file*.

**Where to put it:** generated `.conf` files are saved **next to the
script**, and they contain your private key. Keep the script in a local
folder, such as `Documents\nordvpn` or `~/nordvpn`. Avoid folders that sync
to a cloud (OneDrive, Dropbox, iCloud Drive, Google Drive and the like),
unless you only use the QR code or delete the file right after importing
it.

---

## Get a NordVPN access token

1. Log in at [my.nordaccount.com](https://my.nordaccount.com) → **NordVPN**.
2. Choose **Set up NordVPN manually**. NordVPN e-mails you a verification
   code; enter it.
3. Open the **Access token** tab → **Generate new token**.
   - A **30-day token** is the safer choice.
   - A non-expiring token should only be used with multi-factor
     authentication enabled on your account.
4. The token is **shown only once**: copy it now.
5. When you're done with the script, come back and **revoke** the token.

NordVPN's guide: [How to use a token with NordVPN on Linux](https://support.nordvpn.com/hc/en-us/articles/20286980309265-How-to-use-a-token-with-NordVPN-on-Linux)
(the token part applies to every platform). The menu labels may change
over time.

---

## Run it

Open a terminal **in the folder that holds the script**, then:

| System | Command |
|---|---|
| Windows (python.org install) | `py -3 nord_wg_config.py` |
| Windows (Microsoft Store install) | `python nord_wg_config.py` |
| macOS / Linux | `python3 nord_wg_config.py` |

Optional: add `-I` (isolated mode, e.g. `py -3 -I nord_wg_config.py`).
Python then ignores environment variables and the current folder's
modules. It's a cheap extra safeguard for a script that handles a
credential.

### Pasting the token

The token prompt is **hidden**: nothing appears while you paste, which is
normal.

| Terminal | How to paste |
|---|---|
| Windows Terminal | Ctrl+V or right-click |
| Classic Windows console (PowerShell / cmd window) | **Right-click**. Ctrl+V does *not* work here: it inserts a control character instead |
| macOS Terminal / iTerm2 | Cmd+V |
| Linux terminals | Ctrl+Shift+V or right-click → Paste |

Press Enter. The next line must read:

```
Token received: 64 characters, only letters/digits
```

If it shows a different length or `CONTAINS OTHER CHARACTERS`, the paste
went wrong and the script stops before sending anything.

---

## What the script does, step by step

```
You need a NordVPN access token:
  1. Log in at https://my.nordaccount.com -> NordVPN.
  ...
NordVPN access token (hidden; on Windows right-click to paste):
Token received: 64 characters, only letters/digits

Where should the tunnel end?
     1  Europe
     2  The Americas
     3  Asia Pacific
     4  Africa, the Middle East and India
Region (number): 1

Countries in Europe (WireGuard servers):
     1  Albania (AL)  4
     ...
    19  Germany (DE)  322
     ...
Country (number, name or code): de

Germany: 322 WireGuard servers online, lowest load first.

     #  server                 city             load  endpoint
     1  de1234.nordvpn.com     Frankfurt           1  203.0.113.10
     2  de1235.nordvpn.com     Berlin              2  203.0.113.11
     ...
Server (number or hostname, e.g. de1234): 1

--- de1234.nordvpn.com (Frankfurt, Germany, load 1) ---

[Interface]
PrivateKey = <your NordLynx private key>
Address = 10.5.0.2/32
DNS = 103.86.96.100, 103.86.99.100
MTU = 1420

[Peer]
PublicKey = <the server's public key>
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.10:51820
PersistentKeepalive = 25

Your public key (derived from the private key; your WireGuard interface should show it):
  <your NordLynx public key>
All configs from one NordVPN account share this key pair: give each device its own server,
or they will push each other off.

Notes for pfSense users:
  ...

Create: 1 = config file, 2 = QR code, 3 = both, Enter = neither: 3
Saved: .../nordvpn-de1234.conf

Scan with the WireGuard app (+ -> Scan from QR code):
  (QR code)
```

(Counts, server names, IPs and keys above are placeholders. The IPs are
from a range reserved for documentation.)

| Step | What happens |
|---|---|
| 1. Token | Read through a hidden prompt; its shape is checked before it's sent anywhere. |
| 2. Region | NordVPN's own region groups. |
| 3. Country | Every country in that region that has WireGuard servers, with the count. Answer with the number, the country code (`de`) or the name (`germ`, `united k`). |
| 4. Server | Every **online** WireGuard server in that country, lowest load first (servers reporting load 0 last). Answer with the number or the hostname (`de1234`). |
| 5. Config | The complete config. **The private key is shown in clear text.** The public key is derived from it locally. |
| 6. Output | `1` saves `nordvpn-<server>.conf` next to the script (asks before overwriting). `2` prints a QR code. `3` does both. Enter does neither and exits. |

The values that are always the same for NordLynx:

| Field | Value |
|---|---|
| Address | `10.5.0.2/32` (NordLynx gives every client this address) |
| DNS | `103.86.96.100, 103.86.99.100` (NordVPN DNS) |
| MTU | `1420` |
| Endpoint port | `51820` |
| AllowedIPs | `0.0.0.0/0` (all IPv4 traffic) |
| PersistentKeepalive | `25` |

---

## Using the result: client examples

**Always take the endpoint and the server public key from the same run and
the same server.** A key from one server with the address of another never
completes a handshake.

### Phone (iOS / Android) with the QR code

1. Install **WireGuard** from the App Store or Google Play (publisher:
   WireGuard Development Team).
2. Run the script on your computer and choose `2` (QR code) or `3` (both).
3. In the app:
   - **Android**: tap **+** → **Scan from QR code**.
   - **iOS**: tap **+** → **Create from QR code**.
4. Point the camera at the terminal. Give the tunnel a name (e.g.
   `nordvpn-de1234`) and allow the VPN configuration when asked.
5. Switch the tunnel on, then check your public IP (e.g. ipinfo.io).

If the code won't scan, maximise the terminal window or reduce the font
size: the code needs about 70 columns, and wrapped lines break it.

### Windows and macOS app

1. Install WireGuard from [wireguard.com/install](https://www.wireguard.com/install/)
   (macOS: Mac App Store).
2. Run the script and choose `1` (config file).
3. In the app: **Import tunnel(s) from file** → pick `nordvpn-<server>.conf`.
4. Click **Activate**.
5. Delete the `.conf` afterwards; the app keeps its own copy.

The file name becomes the tunnel name. WireGuard for Windows allows at
most 32 characters, which the script respects.

### Linux

**wg-quick** (needs `wireguard-tools`, e.g. `sudo apt install wireguard-tools`):

```bash
sudo install -m 600 nordvpn-de1234.conf /etc/wireguard/nordvpn.conf
sudo wg-quick up nordvpn
sudo wg show
sudo wg-quick down nordvpn
```

The `DNS =` line needs `resolvconf` (package `openresolv`, or the
`resolvconf` shim of systemd-resolved). If `wg-quick` complains, install
it, or delete the `DNS` line and set DNS another way.

To start it at boot: `sudo systemctl enable --now wg-quick@nordvpn`

**NetworkManager** (GNOME/KDE desktops):

```bash
nmcli connection import type wireguard file nordvpn-de1234.conf
```

### pfSense

Written for the WireGuard package on pfSense CE 2.7+ / pfSense Plus. Menu
names may differ slightly between versions.

**1. Install the package**: *System → Package Manager → Available
Packages* → `WireGuard` → Install.

**2. Tunnel**: *VPN → WireGuard → Tunnels → Add Tunnel*

| Field | Value |
|---|---|
| Enable | ticked |
| Description | e.g. `NordVPN` |
| Listen Port | any free UDP port, e.g. `51820` (or `51821` if 51820 is already used by another tunnel) |
| Interface Keys → Private Key | **PrivateKey** from the script. pfSense then shows the public key: it must equal *Your public key* from the script. **Don't press Generate.** |
| Interface Addresses | leave empty (the address goes on the assigned interface, step 4) |

Save.

**3. Peer**: *VPN → WireGuard → Peers → Add Peer*

| Field | Value |
|---|---|
| Tunnel | the tunnel from step 2 |
| Dynamic Endpoint | unticked |
| Endpoint | the server IP from the script, port `51820` |
| Keep Alive | `25` |
| Public Key | the server's **PublicKey** (`[Peer]` section) |
| Allowed IPs | `0.0.0.0/0` |

Save, then **Apply Changes**.

**4. Assign the interface**: *Interfaces → Assignments*, add the new
`tun_wgX`, then open it:

| Field | Value |
|---|---|
| Enable | ticked |
| IPv4 Configuration Type | Static IPv4 |
| MTU | `1420` |
| MSS | optional: `1380` if some websites hang |
| IPv4 Address | `10.5.0.2` / `32` |
| IPv4 Upstream gateway | **Add a new gateway**: IP `10.5.0.1`, name e.g. `NORDVPN_GW` |

Save, Apply. Then under *System → Routing → Gateways*, edit the new
gateway:
- set **Monitor IP** to a public address that answers ping, such as
  `1.1.1.1` (the tunnel peer itself may not answer)
- if pfSense refuses `10.5.0.1` because it's outside the /32, tick
  **Use non-local gateway** under *Advanced*

**5. Outbound NAT**: *Firewall → NAT → Outbound* → mode **Hybrid** →
add a rule:
- Interface: the WireGuard interface
- Source: your LAN subnet (or only the devices that should use the VPN)
- Translation: Interface Address

**6. Send traffic through it**: *Firewall → Rules → LAN*, add a pass rule
**above** the default LAN rule:
- Source: the devices that should use the VPN (an alias is handy)
- Destination: any
- *Advanced → Gateway*: the WireGuard gateway

Only matching devices use the VPN; everything else keeps using your normal
internet connection.

**7. Optional kill switch** (no internet instead of a leak when the tunnel
is down):
- In the pass rule from step 6: *Advanced → Tag* = `VPN_ONLY`.
- Add a floating rule: Action **Block**, **Quick** ticked, Interface
  **WAN**, Direction **out**, *Advanced → Tagged* = `VPN_ONLY`.

**8. DNS (optional)**: devices using pfSense's DNS resolver resolve names
through your normal ISP connection. If that matters, give the VPN devices
NordVPN DNS (`103.86.96.100`) via DHCP static mappings, and make sure that
traffic matches the rule from step 6.

**Check it:**
- *Status → WireGuard*: a recent **latest handshake** and growing
  transfer counters.
- *Status → Gateways*: the WireGuard gateway is **online** (dpinger
  averages over about a minute, so give it time).
- *Diagnostics → Ping*: host `1.1.1.1`, source = the WireGuard interface.
- From a VPN device: ipinfo.io shows the server's country.

**Changing servers later:** run the script again and update only the
**peer's Endpoint and Public Key**, both from the same server. Then Save →
**Apply Changes**. The private key stays. *Status → WireGuard* (or
`wg show` in the shell) shows the live state; if it still shows the old
endpoint, the change wasn't applied.

### OPNsense

*VPN → WireGuard*:
- **Peers**: public key, endpoint address, port `51820`, Allowed IPs
  `0.0.0.0/0`, keepalive `25`.
- **Instances**: private key, tunnel address `10.5.0.2/32`, select the
  peer, MTU `1420`.

Enable WireGuard. Then assign the interface, add a gateway (`10.5.0.1`,
with *Far Gateway* ticked if needed), and add outbound NAT and a
policy-routing rule as in pfSense steps 5–6.

### Other routers

Many routers can **import the `.conf` file directly** (e.g. GL.iNet,
UniFi, ASUS VPN Fusion, OpenWrt LuCI's *Import configuration*). Otherwise,
map the fields:

| Config file | Typical router field |
|---|---|
| `[Interface] PrivateKey` | Private key / local key |
| `[Interface] Address` | Tunnel / interface address: `10.5.0.2/32` |
| `[Interface] DNS` | DNS server(s) |
| `[Interface] MTU` | MTU: `1420` |
| `[Peer] PublicKey` | Peer / server public key |
| `[Peer] Endpoint` | Endpoint host + port `51820` |
| `[Peer] AllowedIPs` | Allowed IPs: `0.0.0.0/0` |
| `[Peer] PersistentKeepalive` | Keepalive: `25` |

---

## Security notes

- **The token** is read through a hidden prompt and sent only to
  `api.nordvpn.com` over HTTPS. It's never stored. Revoke it in your Nord
  Account when you're done.
- **The private key** is your account's NordLynx key, valid for every
  NordVPN server. Treat it like a password:
  - The script prints it, so clear the terminal afterwards (`cls` on
    Windows, `clear` elsewhere) or close the window.
  - Delete `.conf` files once they're imported.
  - Don't save them into cloud-synced folders.
  - `.gitignore` excludes `*.conf`, so a fork won't commit them by
    accident.
- **Nothing to install** means nothing third-party runs with your token.
  The whole tool is one file you can read before running it.
- **Lost or leaked key?** NordVPN ties the NordLynx key to your account.
  Change your account password, revoke all tokens, and contact NordVPN
  support if you think it was misused.

---

## Limitations

- **Tested on Windows 11 with Python 3.12** (PowerShell and Windows
  Terminal).
- **macOS and Linux:** the script uses only portable standard-library
  code and should work in Terminal / any Linux terminal, but it hasn't
  been tested there yet. Reports are welcome.
- **Needs a real terminal** for the hidden token prompt. It won't run in
  Git Bash / MSYS2 (mintty), IDLE, or an IDE's "Run" output pane; it
  stops with a message instead. VS Code's integrated terminal is fine.
- **QR code** needs a terminal with Unicode block characters and ANSI
  colours (any modern terminal) and roughly 70 × 40 characters of space.
- **One key pair per account.** Every config generated from the same
  account has the same private key. Two devices on the **same server**
  push each other off, so use a different server per device. NordVPN's
  limit on simultaneous devices still applies.
- **IPv4 only.** IPv6 doesn't go through the tunnel. If your network has
  IPv6, either disable it on the device, or add `, ::/0` to `AllowedIPs`
  so IPv6 is dropped instead of leaking past the VPN.
- **NordVPN only**, and it relies on NordVPN's API, which isn't officially
  documented. If NordVPN changes it, the script may break.
- **Server lists are a snapshot.** Load and availability change by the
  minute; a server that was online when you ran the script can be retired
  later. If it stops working, run the script again and pick another one.
- **Some servers may not answer from some networks.** If one server never
  completes a handshake, try a server in a different IP range.
- **No IPv6 endpoints, no obfuscated or TCP servers.** It lists standard
  WireGuard (UDP 51820) servers only.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `py` / `python3` is not recognised | Python isn't installed or not on PATH. See [Installing Python](#installing-python). On Windows try `python` instead of `py -3`. |
| `No terminal for the hidden prompt` | Started from Git Bash, an IDE output pane or a pipe. Use PowerShell / Windows Terminal, macOS Terminal, or a Linux terminal. |
| `Token received: … CONTAINS OTHER CHARACTERS` or a wrong length | The paste went wrong (often Ctrl+V in the classic Windows console). Run it again and **right-click** to paste. |
| `NordVPN API 400 … code 100106` | The token arrived garbled (bad paste). Run it again and paste carefully. |
| `NordVPN API 401 … code 101301` | The token is wrong, expired or revoked. Generate a new one. |
| `CERTIFICATE_VERIFY_FAILED` (macOS) | python.org Python without certificates. Run `/Applications/Python 3.x/Install Certificates.command`. |
| Other network errors / timeouts | No internet, a proxy, or a firewall blocking `api.nordvpn.com`. Try again on another network. |
| Tunnel shows **0 B received**, no handshake | The endpoint and public key come from different servers (use one server's values), outgoing UDP 51820 is blocked on your network, or the server doesn't answer from your network: pick another server, ideally in a different IP range. |
| pfSense: the tunnel's public key differs from *Your public key* | The wrong private key is in the tunnel (e.g. *Generate* was pressed). Paste the script's private key again, Save, Apply. |
| pfSense: handshake OK, but the endpoint in *Status → WireGuard* is still the old one | The peer change wasn't applied. Click **Apply Changes**, or restart the WireGuard service. |
| pfSense: handshake OK, gateway shows **down** | Wait about a minute (dpinger averages). If it stays down, set the gateway's Monitor IP to `1.1.1.1`. |
| Connected, but no websites load | DNS (try NordVPN DNS `103.86.96.100`), MTU (keep 1420; try 1380 or MSS clamping), or on routers missing outbound NAT. |
| Connection drops every few minutes / handshakes flap | Another device uses the same account key **on the same server**. Give each device its own server. |
| IP-check site shows the wrong country | GeoIP databases lag behind address re-assignments. Check several (ipinfo.io, ip-api.com) before blaming the server. |
| QR code won't scan | Terminal too narrow (lines wrap): maximise it or reduce the font size. Hold the phone steady and straight on. |
| `wg-quick: resolvconf: command not found` (Linux) | Install `openresolv` (or systemd-resolved's `resolvconf`), or remove the `DNS` line. |
| WireGuard for Windows rejects the file | Edited with an editor that added a BOM or changed the name to more than 32 characters. Generate a fresh file. |

---

## How it works

| Step | Request |
|---|---|
| Your private key | `GET https://api.nordvpn.com/v1/users/services/credentials` with HTTP basic auth `token:<access token>` → `nordlynx_private_key` |
| Regions | `GET /v1/servers/groups` (groups of type `regions`) |
| Countries in a region | `GET /v1/servers?filters[servers_groups][id]=<region>&filters[servers_technologies][identifier]=wireguard_udp` with sparse fields (country only) |
| Servers in a country | `GET /v1/servers?filters[servers_technologies][identifier]=wireguard_udp&filters[country_id]=<id>` → hostname, IP, load, city, WireGuard public key and status |

The public key is computed locally from the private key with X25519
(RFC 7748, implemented in the file and self-tested at every start against
the RFC's test vector). The QR code is generated locally as well (ISO/IEC
18004, byte mode, error-correction level L, modelled on Project Nayuki's
reference encoder). No key or token ever leaves your machine except the
token's single request to NordVPN.

## License

MIT, see [LICENSE](LICENSE).
