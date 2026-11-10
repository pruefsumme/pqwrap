<h1 align="center">
  <img src="docs/assets/pqwrap-readme-logo.png" alt="pqwrap" width="420">
</h1>

<p align="center">
  Post-quantum TLS in front of legacy services, without changing the service.
</p>

`pqwrap` is a TLS-terminating TCP proxy that adds post-quantum key exchange in front of an existing service.

## Quick start

Requires Go 1.27 or later and a certificate and private key for the client-facing connection.

Set the certificate paths and backend address in `config/pqwrap.yaml`, then build and run:

```bash
go build -o pqwrap .
./pqwrap -config config/pqwrap.yaml
```

### Docker

```bash
docker build -t pqwrap .
docker run --rm -p 443:443 \
  -v ./config:/etc/pqwrap:ro \
  -v ./certs:/certs:ro \
  pqwrap
```

Run the container on a network where the configured backend address is reachable.

## Configuration

All runtime settings are in `config/pqwrap.yaml`:

```yaml
listen: ":443"
profile: hybrid
cert: /certs/pqwrap.crt
key: /certs/pqwrap.key
backend:
  address: backend:443
  tls: true
  name: backend
  ca: /certs/backend-ca.crt
```

`backend.tls` enables TLS to the backend and certificate verification. Set it to `false` only when the backend accepts plain TCP. If `backend.ca` is omitted, the system trust store is used.

## Key exchange profiles

`hybrid` is the default and recommended starting point.

| Profile | Key exchange | Use |
| --- | --- | --- |
| `hybrid` | X25519 + ML-KEM-768 or P-256 + ML-KEM-768 | Post-quantum and classical components; classical-only clients are rejected |
| `compat` | Hybrid groups plus X25519 and P-256 | Allows older clients; classical connections are logged as warnings |
| `high` | P-384 + ML-KEM-1024 | Stronger hybrid profile |
| `pq` | ML-KEM-1024 | Post-quantum only, without a classical component |
| `classic` | X25519 or P-256 | Classical baseline measurements only |

## Tunnel mode

For clients that can't do post-quantum TLS either, two `pqwrap` instances form a tunnel. The client's own TLS passes through unchanged, so `pqwrap` never sees the plaintext and the server keeps its certificate:

```
legacy client ──TLS──▶ pqwrap (client) ══PQ-TLS══▶ pqwrap (server) ──TLS──▶ legacy server
```

Next to the client:

```yaml
mode: client
listen: "127.0.0.1:443"
profile: hybrid
backend:
  address: gateway.example:443   # the pqwrap in server mode
  name: gateway.example
  ca: /certs/ca.crt
```

Next to the server, a normal `pqwrap` with `backend.tls: false` passes the bytes on as they are:

```yaml
mode: server
listen: ":443"
profile: hybrid
cert: /certs/gateway.crt
key: /certs/gateway.key
backend:
  address: legacy:443
  tls: false
```

The legacy client then connects to the tunnel entry instead of the server, e.g. via DNS or `/etc/hosts`. The tunnel carries any TCP protocol, not only TLS.

### Several services on one machine

One `pqwrap` in client mode can protect several services, one route each. The `client` subcommands add a route to the config and point the service's name at a free loopback address in `/etc/hosts`, so apps keep using the usual name:

```bash
sudo pqwrap client add barkasse.intern:443 --via gateway.example:8443 --ca /certs/ca.crt -config config/pqwrap.yaml
sudo pqwrap client add mail.intern:993     --via gateway.example:8993 --ca /certs/ca.crt -config config/pqwrap.yaml
pqwrap client list -config config/pqwrap.yaml
sudo pqwrap client remove mail.intern -config config/pqwrap.yaml
kill -HUP <pid>   # the running pqwrap opens and closes the listeners
```

`sudo` is only needed for `/etc/hosts`; without it, `add` prints the line to add by hand. The result in the config:

```yaml
mode: client
profile: hybrid
routes:
  - name: barkasse.intern
    listen: 127.0.0.2:443
    remote:
      address: gateway.example:8443   # a pqwrap in server mode in front of barkasse
      ca: /certs/ca.crt               # name: defaults to the host of address
```

Each route needs its own exit, because a `pqwrap` in server mode forwards to exactly one backend. Apps that connect to a fixed IP address instead of a name are not redirected this way.

## Operations and logs

Send `SIGHUP` to reload the configuration and profile without restarting the process:

```bash
kill -HUP <pid>
# or, with Docker Compose:
docker compose kill -s HUP pqwrap
```

In server mode the listen address is fixed at startup and changes to it require a restart. In client mode a reload opens and closes route listeners as needed. Switching between server and client mode always needs a restart.

Each connection is reported as a JSON log entry. For example:

```json
{"msg":"connection","client":"172.21.0.1:54190","group":"X25519MLKEM768","pq":true,"handshake_ms":3.48}
```

`pq: true` indicates a post-quantum key exchange. Rejected handshakes are logged with `"msg":"rejected"`. `"backend_group":"none"` means the bytes are passed to the backend as they are, without TLS from `pqwrap`.

## Verify

Run the unit tests and, with `pqwrap` listening locally, check which client groups are accepted:

```bash
go test ./...
./check.sh localhost:443 certs/ca.crt backend
```

`check.sh` requires OpenSSL 3.5 or later. The CA file is optional.

## Security model

- In server mode, `pqwrap` terminates client TLS and can access the decrypted traffic; protect the host and its credentials accordingly. In tunnel mode it only sees the client's own TLS. The tunnel entry verifies the exit's certificate, but the exit does not authenticate the entry: anyone who reaches the exit can use it like the backend itself.
- In tunnel mode only the hop between the two `pqwrap` instances is post-quantum protected; the hops from the app to the entry and from the exit to the server keep the app's own, usually classical, TLS. Against Harvest Now, Decrypt Later this works only if those hops can't be recorded: run the entry on the same host as the app (loopback) and the exit on or next to the server. A route that doesn't listen on loopback is logged as a warning.
- The client-facing connection uses the selected key exchange profile. The backend connection is a separate hop and is not post-quantum protected.
- Keep the backend hop on a trusted network. When backend TLS is enabled, `pqwrap` verifies the backend certificate; when disabled, backend traffic is plaintext.
- `pqwrap` uses Go's TLS implementation and does not implement cryptographic algorithms itself.
