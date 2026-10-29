#!/usr/bin/env python3
"""NordVPN (NordLynx) -> WireGuard config for the WireGuard apps, pfSense and other routers.

    python3 nord_wg_config.py        (Windows: py -3 nord_wg_config.py)

Standard library only. Run it in a real terminal: the token prompt is hidden.

1. Asks for a NordVPN access token and says where to get one.
2. Region (NordVPN's own groups), 3. country in that region, 4. every online
   WireGuard server in that country, lowest load first.
5. Prints the full config, private key included, plus the public key that
   belongs to it (what your WireGuard interface should show).
6. Writes a .conf next to this script, shows a QR code, both, or neither.

The private key comes from GET api.nordvpn.com/v1/users/services/credentials
(basic auth token:<token>); the token goes nowhere else. Endpoint and peer
public key always come from the same server entry.

API answers: 400 code 100106 = malformed header (bad paste); 401 code 101301 =
well-formed but wrong or expired token.
"""
import argparse
import base64
import getpass
import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

API = "https://api.nordvpn.com/v1"
UA = {"User-Agent": "Mozilla/5.0 (nord_wg_config)"}
NORD_DNS = "103.86.96.100, 103.86.99.100"
TOKEN_HELP = """\
You need a NordVPN access token:
  1. Log in at https://my.nordaccount.com -> NordVPN.
  2. "Set up NordVPN manually" -> enter the code Nord e-mails you.
  3. Tab "Access token" -> "Generate new token" (30-day; a non-expiring one
     only with MFA on). It is shown once: copy it.
  4. Revoke it there when you're done."""

# --- X25519 (RFC 7748), only to derive the public key from the private key ---
P = 2**255 - 19


def x25519(k, u):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def public_key(private_b64):
    return base64.b64encode(x25519(base64.b64decode(private_b64), (9).to_bytes(32, "little"))).decode()


def selftest():
    """RFC 7748 section 6.1 test vector (Alice)."""
    priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    want = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    got = x25519(priv, (9).to_bytes(32, "little")).hex()
    if got != want:
        sys.exit(f"X25519 self-test failed: {got}")


# --- QR code (ISO/IEC 18004): byte mode, error correction L, after Nayuki's reference encoder ---
QR_ECC = [None, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
          28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
QR_BLOCKS = [None, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
             8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25]


def qr_raw_modules(ver):
    n = (16 * ver + 128) * ver + 64
    if ver >= 2:
        align = ver // 7 + 2
        n -= (25 * align - 10) * align - 55
        if ver >= 7:
            n -= 36
    return n


def qr_data_codewords(ver):
    return qr_raw_modules(ver) // 8 - QR_ECC[ver] * QR_BLOCKS[ver]


def gf_mul(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def rs_divisor(degree):
    out, root = [0] * (degree - 1) + [1], 1
    for _ in range(degree):
        for j in range(degree):
            out[j] = gf_mul(out[j], root)
            if j + 1 < degree:
                out[j] ^= out[j + 1]
        root = gf_mul(root, 2)
    return out


def rs_remainder(data, divisor):
    out = [0] * len(divisor)
    for b in data:
        factor = b ^ out.pop(0)
        out.append(0)
        for i, coef in enumerate(divisor):
            out[i] ^= gf_mul(coef, factor)
    return out


def qr_matrix(data):
    """Return the QR code for `data` (bytes) as rows of booleans (True = dark)."""
    for ver in range(1, 41):
        cc_bits = 8 if ver < 10 else 16
        if 4 + cc_bits + 8 * len(data) <= qr_data_codewords(ver) * 8:
            break
    else:
        raise ValueError("too long for a QR code")
    bits = [0, 1, 0, 0] + [(len(data) >> i) & 1 for i in reversed(range(cc_bits))]
    bits += [(b >> i) & 1 for b in data for i in reversed(range(8))]
    capacity = qr_data_codewords(ver) * 8
    bits += [0] * min(4, capacity - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(words) < capacity // 8:
        words.append(pad)
        pad ^= 0xEC ^ 0x11

    # Error correction, then interleave the blocks.
    nblocks, ecclen, raw = QR_BLOCKS[ver], QR_ECC[ver], qr_raw_modules(ver) // 8
    nshort, shortlen = nblocks - raw % nblocks, raw // nblocks
    div, blocks, k = rs_divisor(ecclen), [], 0
    for i in range(nblocks):
        dat = words[k:k + shortlen - ecclen + (0 if i < nshort else 1)]
        k += len(dat)
        ecc = rs_remainder(dat, div)
        blocks.append(dat + ([0] if i < nshort else []) + ecc)
    codewords = [blk[i] for i in range(len(blocks[0])) for j, blk in enumerate(blocks)
                 if i != shortlen - ecclen or j >= nshort]

    size = ver * 4 + 17
    mods = [[False] * size for _ in range(size)]
    func = [[False] * size for _ in range(size)]

    def put(x, y, dark):
        mods[y][x], func[y][x] = dark, True

    for i in range(size):  # timing patterns
        put(6, i, i % 2 == 0)
        put(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):  # finder patterns + separators
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                if 0 <= cx + dx < size and 0 <= cy + dy < size:
                    put(cx + dx, cy + dy, max(abs(dx), abs(dy)) not in (2, 4))
    if ver > 1:  # alignment patterns
        n = ver // 7 + 2
        step = (ver * 8 + n * 3 + 5) // (n * 4 - 4) * 2
        pos = [6] + sorted(size - 7 - i * step for i in range(n - 1))
        for i, ax in enumerate(pos):
            for j, ay in enumerate(pos):
                if (i, j) not in ((0, 0), (0, n - 1), (n - 1, 0)):
                    for dy in range(-2, 3):
                        for dx in range(-2, 3):
                            put(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)

    def put_format(mask):
        fdata = 1 << 3 | mask  # error correction L = 01
        rem = fdata
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        f = (fdata << 10 | rem) ^ 0x5412
        bit = [(f >> i) & 1 == 1 for i in range(15)]
        for i in range(6):
            put(8, i, bit[i])
        put(8, 7, bit[6])
        put(8, 8, bit[7])
        put(7, 8, bit[8])
        for i in range(9, 15):
            put(14 - i, 8, bit[i])
        for i in range(8):
            put(size - 1 - i, 8, bit[i])
        for i in range(8, 15):
            put(8, size - 15 + i, bit[i])
        put(8, size - 8, True)

    put_format(0)  # reserve the format areas
    if ver >= 7:
        rem = ver
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        v = ver << 12 | rem
        for i in range(18):
            a, b = size - 11 + i % 3, i // 3
            put(a, b, (v >> i) & 1 == 1)
            put(b, a, (v >> i) & 1 == 1)

    # Data in the zigzag order.
    i, right = 0, size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                y = size - 1 - vert if (right + 1) & 2 == 0 else vert
                if not func[y][x] and i < len(codewords) * 8:
                    mods[y][x] = (codewords[i >> 3] >> (7 - (i & 7))) & 1 == 1
                    i += 1
        right -= 2

    masks = [lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
             lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
             lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
             lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0]

    def masked(m):
        put_format(m)
        return [[mods[y][x] ^ (not func[y][x] and masks[m](x, y)) for x in range(size)]
                for y in range(size)]

    def penalty(g):
        # Runs, 2x2 blocks and dark/light balance (rules 1, 2, 4). Any mask decodes;
        # the score only keeps the picture easy for a camera.
        score = 0
        for line in g + [list(c) for c in zip(*g)]:
            run = 1
            for a, b in zip(line, line[1:]):
                if a == b:
                    run += 1
                else:
                    score += run - 2 if run >= 5 else 0
                    run = 1
            score += run - 2 if run >= 5 else 0
        score += 3 * sum(g[y][x] == g[y][x + 1] == g[y + 1][x] == g[y + 1][x + 1]
                         for y in range(size - 1) for x in range(size - 1))
        dark = sum(map(sum, g))
        score += 10 * (abs(dark * 20 - size * size * 10) // (size * size))
        return score

    best = min(range(8), key=lambda m: penalty(masked(m)))
    return masked(best)


def show_qr(text):
    g = qr_matrix(text.encode("ascii"))
    quiet = 4
    size = len(g) + 2 * quiet
    dark = lambda x, y: 0 <= y - quiet < len(g) and 0 <= x - quiet < len(g) and g[y - quiet][x - quiet]
    sys.stdout.reconfigure(encoding="utf-8")  # block characters, also when redirected (-I ignores PYTHONIOENCODING)
    if sys.platform == "win32":  # let the console understand the colour codes
        import ctypes
        k32 = ctypes.windll.kernel32
        h, mode = k32.GetStdHandle(-11), ctypes.c_uint32()
        if k32.GetConsoleMode(h, ctypes.byref(mode)):
            k32.SetConsoleMode(h, mode.value | 4)
    # Black on white whatever the terminal theme; two modules per character cell.
    for y in range(0, size, 2):
        row = "".join(" ▄▀█"[dark(x, y) * 2 + dark(x, y + 1)] for x in range(size))
        print(f"\x1b[30;107m{row}\x1b[0m")


# --- NordVPN API ---------------------------------------------------------------
def get(url, auth=None):
    req = urllib.request.Request(url, headers=dict(UA))
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"token:{auth}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"NordVPN API {e.code}: {e.read()[:200].decode(errors='replace')}")


def account_private_key(token):
    priv = get(f"{API}/users/services/credentials", auth=token).get("nordlynx_private_key")
    if not priv:
        sys.exit("No nordlynx_private_key in the response.")
    return priv


def wg_key(server):
    for t in server.get("technologies", []):
        if t.get("identifier") == "wireguard_udp":
            for m in t.get("metadata") or []:
                if m.get("name") == "public_key":
                    return m["value"], (t.get("pivot") or {}).get("status")
    return None, None


def servers(country_id):
    q = (f"{API}/servers?filters[servers_technologies][identifier]=wireguard_udp"
         f"&filters[country_id]={country_id}&limit=5000")
    out = []
    for s in get(q):
        key, wg_status = wg_key(s)
        if key:
            out.append({"host": s["hostname"], "ip": s["station"], "load": s.get("load", 0),
                        "status": s.get("status"), "wg": wg_status, "key": key,
                        "city": s["locations"][0]["country"]["city"]["name"]})
    return out


def read_token():
    # Hidden prompt. In a classic Windows console Ctrl+V inserts a control character
    # instead of the text; right-click pastes properly.
    if not sys.stdin.isatty():
        sys.exit("No terminal for the hidden prompt. Run it in a terminal "
                 "(on Windows: PowerShell or Windows Terminal, not Git Bash).")
    token = getpass.getpass("NordVPN access token (hidden; on Windows right-click to paste): ").strip()
    plain = all(c.isalnum() or c in "-_" for c in token)
    print(f"Token received: {len(token)} characters, "
          f"{'only letters/digits' if plain else 'CONTAINS OTHER CHARACTERS (paste went wrong?)'}")
    if not token or not plain:
        sys.exit("Not sending that. Run it again and paste the token into the hidden prompt.")
    return token


# --- interactive ---------------------------------------------------------------
def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        sys.exit("\nNo input; stopped.")


def choose(prompt, items, label, match=lambda item, q: False):
    """Numbered list; the answer is a number, or text that `match` accepts for exactly one item."""
    for i, item in enumerate(items, 1):
        print(f"  {i:4}  {label(item)}")
    while True:
        q = ask(prompt).lower()
        if q.isdigit() and 1 <= int(q) <= len(items):
            return items[int(q) - 1]
        hits = [item for item in items if q and match(item, q)]
        if len(hits) == 1:
            return hits[0]
        print("  More than one match; type more or use the number." if hits else "  Not in the list.")


def pick_region():
    regions = [g for g in get(f"{API}/servers/groups") if g["type"]["identifier"] == "regions"]
    print("\nWhere should the tunnel end?")
    return choose("Region (number): ", regions, lambda g: g["title"])


def pick_country(region):
    # Sparse fields: only the country of each WireGuard server in the region (well under 1 MB).
    found = get(f"{API}/servers?filters[servers_groups][id]={region['id']}"
                f"&filters[servers_technologies][identifier]=wireguard_udp&limit=20000"
                f"&fields[servers.locations.country.id]&fields[servers.locations.country.name]"
                f"&fields[servers.locations.country.code]")
    count = Counter((c["id"], c["name"], c["code"]) for c in (s["locations"][0]["country"] for s in found))
    countries = sorted(count, key=lambda c: c[1])
    print(f"\nCountries in {region['title']} (WireGuard servers):")
    return choose("Country (number, name or code): ", countries,
                  lambda c: f"{c[1]} ({c[2]})  {count[c]}",
                  # "de" is Germany's code, not the start of Denmark
                  lambda c, q: q in (c[2].lower(), c[1].lower()) or (len(q) > 2 and c[1].lower().startswith(q)))


def pick_server(rows):
    # Lowest load first; load 0 last, as those servers usually don't report it.
    rows.sort(key=lambda s: (s["load"] == 0, s["load"]))
    example = rows[0]["host"].split(".")[0]
    print(f"\n  {'#':>4}  {'server':22} {'city':16} {'load':>4}  endpoint")
    return choose(f"\nServer (number or hostname, e.g. {example}): ", rows,
                  lambda s: f"{s['host']:22} {s['city'][:16]:16} {s['load']:4}  {s['ip']}",
                  lambda s, q: s["host"].lower().split(".")[0] == q)


def conf_text(priv, s):
    return (f"[Interface]\nPrivateKey = {priv}\nAddress = 10.5.0.2/32\nDNS = {NORD_DNS}\nMTU = 1420\n\n"
            f"[Peer]\nPublicKey = {s['key']}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {s['ip']}:51820\n"
            f"PersistentKeepalive = 25\n")


def save_conf(text, s):
    # Next to the script. WireGuard for Windows names the tunnel after the file:
    # max 32 chars, [A-Za-z0-9_=+.-].
    name = "nordvpn-" + re.sub(r"[^A-Za-z0-9_=+.-]", "", s["host"].split(".")[0]) + ".conf"
    path = Path(__file__).resolve().parent / name
    if path.exists() and not ask(f"{path} exists. Overwrite? [y/N]: ").lower().startswith("y"):
        print("Not saved.")
        return
    path.write_bytes(text.encode("ascii"))  # no BOM: WireGuard for Windows rejects it
    print(f"Saved: {path}")


def main():
    argparse.ArgumentParser(description=__doc__.splitlines()[0]).parse_args()
    selftest()
    print(TOKEN_HELP + "\n")
    token = read_token()
    priv = account_private_key(token)
    del token

    country = pick_country(pick_region())
    rows = [s for s in servers(country[0]) if s["status"] == "online" and s["wg"] == "online"]
    if not rows:
        sys.exit(f"No online WireGuard server in {country[1]}.")
    print(f"\n{country[1]}: {len(rows)} WireGuard servers online, lowest load first.")
    s = pick_server(rows)

    text = conf_text(priv, s)
    print(f"\n--- {s['host']} ({s['city']}, {country[1]}, load {s['load']}) ---\n")
    print(text)
    print(f"Your public key (derived from the private key; your WireGuard interface should show it):\n"
          f"  {public_key(priv)}\n"
          f"All configs from one NordVPN account share this key pair: give each device its own server,\n"
          f"or they will push each other off.\n")
    print("Notes for pfSense users:\n"
          "  - VPN -> WireGuard -> Tunnels: the private key. Address 10.5.0.2/32 on the assigned\n"
          "    interface, MTU 1420 on Interfaces -> (that interface).\n"
          "  - VPN -> WireGuard -> Peers: endpoint, port 51820, public key, allowed IPs 0.0.0.0/0,\n"
          "    keepalive 25. Save, then Apply Changes.\n")
    choice = ask("Create: 1 = config file, 2 = QR code, 3 = both, Enter = neither: ")
    if choice in ("1", "3"):
        save_conf(text, s)
    if choice in ("2", "3"):
        print("\nScan with the WireGuard app (+ -> Scan from QR code):\n")
        show_qr(text)
    print("\nThe private key is in this window's scrollback: clear the terminal when done, "
          "and revoke the token.")


if __name__ == "__main__":
    main()
