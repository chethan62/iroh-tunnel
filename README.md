# iroh-tunnel

A TCP/UDP tunnel over [iroh](https://www.iroh.computer/) — QUIC, hole-punching,
relay fallback. Give someone a ticket and they reach a port on your machine;
traffic goes peer-to-peer when a direct path can be punched and falls back to a
public relay when it can't.

```bash
npm install --omit=dev
# publish a local port
node bin/iroh-tunnel.js share 8080
#   ticket: endpoint…
# on the other side
node bin/iroh-tunnel.js connect 'endpoint…' --port 9090
```

As a library:

```js
const { Tunnel, lookup } = require('iroh-tunnel')

const srv = new Tunnel({ server: true, port: 8080 })
await srv.ready()
console.log(srv.url)          // the ticket to hand out

const cli = new Tunnel({ client: true, key: srv.url, port: 9090 })
await cli.ready()             // 127.0.0.1:9090 now reaches the peer's 8080

await lookup(srv.url)         // { endpointId, addrs, relayUrl } | null
```

`{ udp: true }` tunnels datagrams instead of a byte stream — they ride native
QUIC datagrams, so message boundaries are preserved.

## Why this exists as its own project

It was written as an opt-in second engine inside
[holesail-gui](https://github.com/chethan62/holesail-gui) and could never ship
there: `@number0/iroh` ships **NAPI-RS prebuilds requiring Node >= 20.3**, and
that app's packaged builds run their worker under
[Bare](https://github.com/holepunchto/bare), which loads only its own addon ABI.
A tunnel that cannot be packaged with the app it lives in is a separate project,
so the GUI went back to a single engine and this kept the research, the UDP
work, and the tests.

## Honest limits

- **Throughput.** ~4 MB/s of bulk transfer, measured, against ~29 MB/s for
  `holesail`'s engine on the same box. The JS binding moves payload bytes one
  array element at a time; that is the binding, not the network.
- **Node only.** No Bare, no Android, no browser — see above.
- **Public relays by default.** iroh's default configuration uses n0's public
  relays when a direct path fails. They see ciphertext only, but they are in the
  connection path; `iroh-relay` can be self-hosted.
- **Tickets are secrets.** Possession is access — there is no separate auth.
- **The ALPN is its own** (`iroh-tunnel/1`), so tickets from here do not
  interoperate with other iroh apps.

## Tests

`npm test` runs one self-contained end-to-end pass: a TCP tunnel carrying a
payload through the DHT, a reachability `lookup`, a UDP datagram round trip, the
oversize-datagram rule (dropped, not truncated, tunnel survives), and the
invalid-key path — which must reject the key *without* echoing any of it into
the error message.

It needs network access and takes ~1–2 minutes.

## License

MIT — see [LICENSE](LICENSE). The iroh dependency is MIT/Apache-2.0.
