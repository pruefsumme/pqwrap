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

## Operations and logs

Send `SIGHUP` to reload the configuration and profile without restarting the process:

```bash
kill -HUP <pid>
# or, with Docker Compose:
docker compose kill -s HUP pqwrap
```

The listen address is fixed at startup. Changes to that address require a restart.

Each connection is reported as a JSON log entry. For example:

```json
{"msg":"connection","client":"172.21.0.1:54190","group":"X25519MLKEM768","pq":true,"handshake_ms":3.48}
```

`pq: true` indicates a post-quantum key exchange. Rejected handshakes are logged with `"msg":"rejected"`.

## Verify

Run the unit tests and, with `pqwrap` listening locally, check which client groups are accepted:

```bash
go test ./...
./check.sh localhost:443 certs/ca.crt backend
```

`check.sh` requires OpenSSL 3.5 or later. The CA file is optional.

## Security model

- `pqwrap` terminates client TLS and can access the decrypted traffic; protect the host and its credentials accordingly.
- The client-facing connection uses the selected key exchange profile. The backend connection is a separate hop and is not post-quantum protected.
- Keep the backend hop on a trusted network. When backend TLS is enabled, `pqwrap` verifies the backend certificate; when disabled, backend traffic is plaintext.
- `pqwrap` uses Go's TLS implementation and does not implement cryptographic algorithms itself.
