<h1 align="center">
  <img src="docs/assets/pqwrap-readme-logo.png" alt="pqwrap" width="420">
</h1>

<p align="center">
  Post-quantum TLS for services and devices that can't be updated.
</p>

`pqwrap` is a small TCP proxy that adds a hybrid post-quantum key exchange (X25519 + ML-KEM-768) to connections whose endpoints can't do it themselves. Recorded traffic then stays unreadable even for a future quantum computer. There are three ways to use it:

```
1. old server      client ══PQ-TLS══▶ pqwrap ──▶ server
2. old client      client ──▶ pqwrap ══PQ-TLS══▶ pqwrap ──▶ server
3. fixed device    device ──▶ gateway (firewall ▶ pqwrap) ══PQ-TLS══▶ pqwrap ──▶ server
```

In 2 and 3 the client's own TLS passes through the tunnel untouched: `pqwrap` never sees the plaintext and the server keeps its certificate.

## Install

Needs Go 1.27 or later.

```bash
go build -o pqwrap .
./pqwrap -config config/pqwrap.yaml
```

Or with Docker: `docker build -t pqwrap .`, then mount the config at `/etc/pqwrap` and your certificates.

## 1. In front of an old server

Clients that already support ML-KEM (current browsers) connect to `pqwrap`, which forwards to the unchanged server.

```yaml
listen: ":443"
profile: hybrid
cert: /certs/pqwrap.crt
key: /certs/pqwrap.key
backend:
  address: backend:443
  name: backend              # name in the backend's certificate
  ca: /certs/backend-ca.crt  # omit to use the system trust store
```

## 2. Tunnel for old clients

If the client can't do ML-KEM either, put one `pqwrap` next to the client (entry) and one next to the server (exit).

Exit, next to the server:

```yaml
listen: ":443"
profile: hybrid
cert: /certs/exit.crt
key: /certs/exit.key
client_ca: /certs/ca.crt   # only entries with a certificate from this CA get through
backend:
  address: legacy:443
  tls: false               # pass the client's own TLS on as it is
```

Entry, on the same machine as the client. Start with a config that only says `mode: client`, then add one route per service:

```bash
sudo pqwrap client add legacy.intern:443 --via gateway.example:443 \
    --ca ca.crt --cert entry.crt --key entry.key
pqwrap client list
sudo pqwrap client remove legacy.intern
```

`add` gives the service a loopback address and points its name there in `/etc/hosts` (that is what `sudo` is for), so apps keep using the usual name. A running `pqwrap` picks up the change with `kill -HUP <pid>`.

## 3. Transparent mode for devices you can't touch

A sensor with fixed firmware can't be pointed at an entry. Run the entry on the gateway next to it instead and let the firewall hand the device's connections to `pqwrap`. The device keeps dialing its server as always.

```yaml
mode: client
profile: hybrid
transparent: ":9040"                # one port for all redirected connections
routes:
  - name: broker
    intercept: 192.168.1.20:8883    # the address the device dials
    remote:
      address: gateway.example:8883 # the exit
      ca: /certs/ca.crt
```

```bash
pqwrap client rules | sudo nft -f -   # load the nftables redirect
sudo nft delete table ip pqwrap       # remove it again
```

Linux and IPv4 only. The rules are not persistent; add them to your nftables config to keep them across reboots. Redirected connections without a matching route are closed, never passed on unprotected. `pqwrap` must run on the host itself, not behind a userspace port forwarder such as rootless Docker.

## Profiles

| Profile | Allows | Use |
| --- | --- | --- |
| `hybrid` | X25519MLKEM768, SecP256r1MLKEM768 | Default. Classical-only clients are rejected |
| `high` | SecP384r1MLKEM1024 | Stronger hybrid |
| `compat` | hybrid plus X25519, P-256 | Transition: old clients get in, logged as a warning |
| `pq` | MLKEM1024 | Comparison only, no classical part |
| `classic` | X25519, P-256 | Baseline measurements only |

Switch profiles or routes without a restart: edit the config and send `SIGHUP`.

## Logs

One JSON line per connection. `"pq": true` means the key exchange was quantum-safe:

```json
{"msg":"connection","client":"172.21.0.1:54190","group":"X25519MLKEM768","pq":true,"handshake_ms":3.48}
```

Rejected clients are logged with `"msg":"rejected"` and the groups they offered.

## Limits

- Only the hop that `pqwrap` protects is post-quantum. The hops to the old server and from the old client stay classical, so keep `pqwrap` as close to them as possible.
- A tunnel needs an exit you run yourself. It can't protect connections to someone else's server.
- In mode 1 `pqwrap` terminates TLS and sees the plaintext. In a tunnel it doesn't.
- Use your own CA for the tunnel (`--ca`, `client_ca`). `pqwrap` warns at start about routes without one and about exits that let anyone in.
- Certificates use classical signatures. `pqwrap` uses Go's `crypto/tls` and implements no cryptography itself.

## Tests

```bash
go test ./...
./check.sh localhost:443 certs/ca.crt backend   # which groups a running pqwrap accepts, needs OpenSSL 3.5
```
