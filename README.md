# MikroTik RouterOS Backup Decoder

> **Why this exists (the honest story)**
>
> One day all I had was a RouterOS `.backup` file — no `/export` `.rsc`, no live access to
> the router, just the binary blob. I needed to actually *see* the configuration inside it
> (a classic "I forgot the password / lost access to my own device" situation). RouterOS
> backups are an opaque binary format, so I sat down and reverse-engineered it well enough
> to read my own config back out. This tool is the result.
>
> This is honest hobby / forensics work. **There is no malicious intent behind it.**
>
> **A note on accuracy:** I have **not** finished analyzing every internal enum/bitmask in
> the format. So this is **not a 1:1 reconstruction** of the running config. A large part of
> the configuration is decoded into clean, human-readable fields; the rest is still shown by
> its raw numeric id or enum code. See [Limitations](#limitations). I'd rather show an
> honest "I don't know what this id means yet" than guess and mislead you.

---

## ⚠️ Status & scope (read this)

- **Experimental and unsupported.** This is an independently reverse-engineered hobby tool.
  It is **not** affiliated with, endorsed by, or supported by MikroTik. There is no warranty,
  no support, and no roadmap. Use it at your own risk.
- **Authorized systems only.** Use it strictly on backups of devices **you own** or are
  **explicitly authorized in writing** to analyze. Nothing here is intended to facilitate
  access to systems you do not control.
- **No version-compatibility guarantee.** The format was inferred from specific RouterOS
  backups. Field meanings, ids, and enum codes **vary between RouterOS versions** and may be
  wrong or incomplete for yours. Treat every decoded value as best-effort, not authoritative.
- **Not a credential-recovery or security-bypass tool.** Decoding the configuration does
  **not** require any password. The optional password *verification* utility only checks a
  password you already believe is yours against your own backup — it cannot reveal, recover,
  or bypass anything (the stored value is a one-way verifier). Using it, or this tool, to
  obtain access you are not entitled to is out of scope and prohibited (see Disclaimer).

---

## What it does

It parses MikroTik RouterOS `*.backup` files (the output of `/system backup save`) and
turns the internal binary "store" / item (`M2`) serialization into:

- a clean, queryable **JSON** file, and
- a readable **text tree**.

It also understands the **container encryption header** and can verify user passwords
against the **EC-SRP5** credential scheme RouterOS uses (see below).

### Intended use

**Forensics, auditing, and backup analysis** — for example:

- Inspecting **your own** configuration when all you have is the backup file.
- Auditing what is actually stored in a backup (users, firewall rules, BGP peers, addresses…).
- Comparing two backups, or migrating settings, without a running router.

---

## ⚠️ Authorization — read this first

**Use this tool only on systems you own, or that you are explicitly authorized to
analyze.** Backup files frequently contain sensitive material (addressing, BGP/peering
secrets, certificates, and one-way password verifiers). Treat them accordingly.

If you are not the owner of the device and do not have written permission, **stop here.**

---

## Features

- **Container parsing** — validates the magic and length header; reports the format
  (plaintext / RC4-encrypted).
- **Full property decoder** — every value type in the format (booleans, 8/32/64-bit and
  128-bit integers, strings, nested `M2` messages, raw blobs, and arrays).
- **Evidence-based field naming** — common/identifiable properties are given their RouterOS
  names (e.g. `name`, `comment`, `disabled`, `address`, `netmask`, BGP `remote.as`,
  firewall `chain`/`action`, DNS `cache-size`, …). Unknown ids are shown verbatim.
- **Relational resolution** — e.g. a user's group is stored as a permission bitmask and is
  resolved back to the group name (`group: full`).
- **Smart binary rendering** — 6-byte blobs become MAC addresses, SSH keys become
  `ssh-rsa AAAA…`, printable blobs become text; genuinely random material (salts, hashes)
  stays as hex.
- **EC-SRP5 password verification** — recompute and check candidate passwords for **your
  own** backup (one-way verifier; see below).

---

## Build

Requires Go 1.24+.

```sh
go build -o mikrotik-backup .
```

Or run it directly without building:

```sh
go run . router.backup
# (go run main.go router.backup also works — it is a single-file program)
```

There are no external dependencies (standard library only).

---

## Usage

```sh
mikrotik-backup [-out prefix] [-password pass] [-wordlist file] <backup-file>
```

| Flag | Description |
| --- | --- |
| `-out <prefix>` | Output file prefix. Writes `<prefix>.json` and `<prefix>.txt`. Default: `output`. |
| `-password <pass>` | Password for **RC4-encrypted** backups (older RouterOS). |
| `-wordlist <file>` | Audit user passwords against this wordlist (EC-SRP5). |
| `-all` | Show **all** fields, including unnamed defaults (`false`/`0`/empty). |

If `-wordlist` is not given but a file named `wordlist.txt` exists in the working directory,
it is used automatically.

**Concise by default.** Most of a record's raw properties are noise. By default the tool:

- **omits unnamed fields at their default** (`false` / `0` / empty), and
- **omits unnamed fields that hold the same value across a store's records** (uniform
  internal/structural defaults — e.g. an unchanging limit present on every firewall rule, or
  identical ethernet settings on every interface).

Named fields are always shown (even at default). Nothing is guessed or renamed — hidden
fields are simply uninformative. Use **`-all`** for the full, unfiltered forensic dump.

### Examples

```sh
# Decode a plaintext backup -> output.json / output.txt
go run . router.backup

# Custom output name
go run . -out myrouter router.backup

# Decrypt an RC4-encrypted backup
go run . -password 'mypassword' router.backup

# Audit user passwords (your own backup) against a wordlist
go run . -wordlist wordlist.txt router.backup
```

---

## Output

- **`<prefix>.json`** — flattened, queryable. Empty stores are collapsed into an
  `empty_stores` name list; each record is a keyed `fields` object with resolved values.
- **`<prefix>.txt`** — full forensic tree: every property as `id [type] = value (hints)`,
  including raw hex for unknown types.

The console prints a summary (format, length check, store/record counts, non-empty stores)
and, if a wordlist is used, the password audit result.

---

## How it works (format)

All integers are little-endian.

```
Header : magic (u32) + length (u32)        # 0xB1A1AC88 plaintext, 0x7291A8EF RC4
Stores : repeated until EOF
  name_len (u32) + name
  dir_len  (u32) + directory               # 12 bytes per record: [id][size][pad]
  data_len (u32) + data                    # records, each: [len u16]["M2"][payload]
```

Each record payload is a sequence of properties `[id u24][type u8][value]`, where the type
byte is a small bitfield (e.g. `0x08`=u32, `0x10`=u64, `0x18`=128-bit, `0x21`=string,
`0x29`=nested message, the `0x80` bit marks an array, …).

### Password verification (EC-SRP5)

RouterOS 6.45+ does **not** store passwords. It stores a one-way verifier:

```
inner = SHA256(username | ":" | password)
k     = SHA256(salt | inner)               # 32-byte scalar
(X,Y) = k * G        on Curve25519 in short-Weierstrass form
u     = (X + C) mod p                       # Montgomery u-coordinate
stored = u (32 bytes) || (Y & 1)            # x-coordinate + y-parity
```

This verifier **cannot be reversed** to the plaintext (that would require solving the
elliptic-curve discrete-log problem) — the tool cannot reveal or recover a password. The
optional `-wordlist` mode only **checks** candidates you supply: it recomputes the verifier
for each candidate and reports whether one matches. It is a *verification* convenience for
confirming a password you already believe is correct on **your own** backup — not a cracker,
recovery, or bypass tool. It is entirely separate from (and not needed for) decoding the
configuration.

---

## Limitations

- **Not a 1:1 config reconstruction.** Roughly a third of all property ids are currently
  mapped to names; the rest are shown by their raw `0xNNNNNN` id.
- **Enums are partially decoded.** Common, confirmed enums are rendered as readable names —
  firewall `protocol` (`tcp`/`udp`/…), `action` (`accept`/`drop`), queue `kind`
  (`pfifo`/`red`/`sfq`/`pcq`/…), logging `target`, and DHCP option `code`. The forensic
  text view shows both (`tcp (6)`); the JSON view shows the clean label.
  **Bitmask-style** fields are *named* but still show their raw code — e.g. `ipsec`
  `enc-algorithm` / `dh-group` / `hash-algorithm` (a single value encodes a *set* of
  algorithms, which can't be reversed reliably from one sample). I haven't reverse-engineered
  those bitmask tables.
- **Encryption:** plaintext backups are fully supported and tested. RC4 decryption is
  implemented per the documented scheme. **AES**-encrypted backups (newer RouterOS) are
  detected but **not** decoded.
- Field names are inferred from observed values cross-referenced with the official RouterOS
  documentation and `/export verbose`. They are best-effort, not guaranteed.

---

## Disclaimer

This tool is provided **as is**, for legitimate forensics, auditing, and analysis of
systems you own or are authorized to work on. **No warranty of any kind.**

The author accepts **no responsibility or liability** for any misuse, including (but not
limited to):

- **Obtaining a backup file that belongs to someone else without permission.**
- **Attempting to recover/crack passwords for the purpose of unauthorized access.**
- **Using any credentials obtained through this tool.**
- **Circumventing or violating the license terms or protection mechanisms of any
  commercial software.**

You are solely responsible for ensuring that your use of this tool is lawful and authorized.
If in doubt, don't.

---

## References

The EC-SRP5 credential scheme was confirmed against:

- Margin Research — "MikroTik Authentication Revealed": <https://margin.re/2022/02/mikrotik-authentication-revealed/>
- hashcat issue #4070: <https://github.com/hashcat/hashcat/issues/4070>
- POC (curve constants): <https://github.com/kyzminskiy/POC-brute-hashes-from-MikroTik-backups>
- Field names cross-referenced with the official RouterOS documentation: <https://help.mikrotik.com/docs/spaces/ROS/>
