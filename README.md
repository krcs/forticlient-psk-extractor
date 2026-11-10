# fcpsk — FortiClient VPN preshared-key extractor

A small Windows console tool that lists the VPN tunnels in a FortiClient
configuration and decrypts their **preshared keys** and **saved usernames**.

It does **not** reimplement FortiClient's crypto — it calls FortiClient's own
`utilsdll.dll!decrypt_buffer`, so results are produced (and validated) by the
same code FortiClient uses.

> **Authorized use only.** This recovers credentials from machines and
> configurations you own or administer (migration, backup, incident recovery).
> The recovered values are secrets — handle and store them accordingly.

---

## How it works

FortiClient stores VPN preshared keys and usernames in its config as
`EncX <hex>` values. The hex decodes to:

```
[ salt 8B ][ marker 2B ][ AES-128-CTR ciphertext ][ HMAC-SHA1 10B ]
```

The AES key is derived from a **context string** plus the salt. For normally
stored values that context is a per-install key the FortiClient *service* holds
only in memory, so the values cannot be decrypted directly off disk.

The workaround: have FortiClient **re-export** the VPN config under a password
**you** choose. That re-encrypts every preshared key and username under a key
derived from *your* password — which you then hand to this tool.

```
┌────────────┐  FCConfig -o export -p PASS  ┌─────────────┐  fcpsk -p PASS  ┌───────────┐
│ live config│ ───────────────────────────► │ vpn_pw.conf │ ──────────────► │ plaintext │
│ (service   │   re-keyed to YOUR password  │ (EncX under │  decrypt_buffer │  PSKs +   │
│  key)      │                              │  PASS)      │  (utilsdll.dll) │  usernames│
└────────────┘                              └─────────────┘                 └───────────┘
```

---

## Usage

### 1. Re-export the VPN config under a known password

On the target PC, in an **elevated** Command Prompt:

```bat
"C:\Program Files\Fortinet\FortiClient\FCConfig.exe" ^
    -f "%CD%\vpn_pw.conf" -m vpn -o export -p MyPass12345
```

### 2. Decrypt

```bat
fcpsk vpn_pw.conf -p MyPass12345
```

```
TUNNEL      | TYPE  | SERVER            | USERNAME  | PRESHARED KEY
------------+-------+-------------------+-----------+------------------
<tunnel-1>  | IPsec | <server-1>        | <user-1>  | <preshared-key-1>
<tunnel-2>  | IPsec | <server-2>        | <user-2>  | <preshared-key-2>
...

N tunnel(s): N IPsec, 0 SSL. Preshared keys recovered: N/N.
```

### Options

| Option | Meaning |
| --- | --- |
| `<config.conf>` | Config to read (default `vpn_pw.conf`). |
| `-p, --password` | The export password / context. Prompted for if omitted. |
| `--fcdir <dir>` | FortiClient dir with `utilsdll.dll` (default `C:\Program Files\Fortinet\FortiClient`). |
| `--show-hex` | Also print plaintext as hex (verification). |
| `-h, --help` | Help. |

---

## Build

Requires the .NET 8 SDK.

```bash
# compile / run (on Windows)
dotnet run --project src/ForticlientPskExtractor -- vpn_pw.conf -p MyPass12345

# single self-contained .exe (no runtime needed on the target)
dotnet publish src/ForticlientPskExtractor -c Release -r win-x64 --self-contained
# -> src/ForticlientPskExtractor/bin/Release/net8.0/win-x64/publish/fcpsk.exe
```

The project builds anywhere (plain `net8.0` TFM) but **runs on Windows x64 only**,
because it loads FortiClient's native DLLs. At runtime `utilsdll.dll` needs its
siblings present in the FortiClient directory (`FCCryptDLL.dll`,
`libcrypto-3-x64.dll`, `libssl-3-x64.dll`, `libcurl.dll`, `nanomsg.dll`, the
VC++ runtimes) — they are there in a normal install.

---

## Scope & limitations

- **Recovers:** IPsec preshared keys, IPsec XAuth usernames, SSL-VPN usernames.
- **Does not recover:** saved account **login passwords** — FortiClient leaves
  `<password/>` empty in every export, so there is nothing to decrypt. Those
  live only in the registry under the per-machine key; recover them where the
  account lives (AD / the account owner) instead.
- Exit codes: `0` success, `1` runtime error, `2` bad arguments / missing input.

## License

MIT — see [LICENSE](LICENSE).
