# pqwrap

pqwrap protects old services against future quantum computers, without changing them.

## The problem

Someone can record your encrypted traffic today and keep it.
In a few years, a quantum computer may be able to break today's encryption.
Then they can read everything they recorded.

New software already uses quantum-safe encryption. Old services often can't be updated.

## The fix

Put pqwrap in front of the old service.

- Users talk to pqwrap. That connection is quantum-safe.
- pqwrap passes everything on to the old service.
- The old service stays exactly as it is.

## Run it

You need Go 1.27 or newer.

```bash
go build .
./pqwrap -config config/pqwrap.yaml
```

Or with Docker:

```bash
docker build -t pqwrap .
docker run -p 443:443 -v ./config:/etc/pqwrap:ro -v ./certs:/certs:ro pqwrap
```

## Set it up

Everything is in one file, `config/pqwrap.yaml`:

```yaml
listen: ":443"              # where users connect
profile: hybrid             # how strict pqwrap is (see below)
cert: /certs/pqwrap.crt     # certificate users see
key: /certs/pqwrap.key
backend:
  address: backend:443      # the old service
  tls: true                 # false if the old service has no encryption at all
  name: backend             # name in the old service's certificate
  ca: /certs/backend-ca.crt
```

Changed something? Tell pqwrap to reload, no restart needed:

```bash
docker compose kill -s HUP pqwrap   # or: kill -HUP <pid>
```

## Profiles

| Profile | What it does |
|---|---|
| `hybrid` | Quantum-safe only. **Start here.** |
| `compat` | Quantum-safe preferred, old clients still allowed (and logged as warnings) |
| `high` | Like `hybrid`, but stronger |
| `pq` | New encryption only, no classic part mixed in |
| `classic` | No quantum safety. Only for comparing speed |

## See what's going on

pqwrap writes one line per connection:

```json
{"msg":"connection","client":"172.21.0.1:54190","group":"X25519MLKEM768","pq":true,"handshake_ms":3.48}
```

- `pq: true` means this connection is quantum-safe.
- `group` is the encryption method that was used.
- Blocked connections show up as `"msg":"rejected"`.

## Check it

```bash
go test ./...
./check.sh localhost:443 certs/ca.crt backend
```

`check.sh` tries different kinds of clients and shows which ones get in.

## Good to know

- The link from pqwrap to the old service is not quantum-safe. Keep it on a trusted network.
- If pqwrap is down, the old service can't be reached.
- pqwrap doesn't build its own encryption. It uses the one built into Go.
