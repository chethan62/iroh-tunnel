/* tunnel.js — a TCP/UDP tunnel over iroh (QUIC + hole-punching + relay
 * fallback; iroh itself is MIT/Apache-2.0, as is this project).
 *
 * Extracted from holesail-gui, where it lived behind that app's worker
 * facade. It is Node-only by nature: @number0/iroh ships NAPI-RS prebuilds
 * (Node >= 20.3), which alt-runtimes like Bare cannot load — that constraint
 * is what made it a separate project rather than a second engine in the GUI.
 *
 * API:  const { Tunnel, lookup } = require('iroh-tunnel')
 *       const t = new Tunnel({ server: true, port: 8080 })   // or client
 *       await t.ready()          -> t.url, t.ticket, t.info
 *       t.on('ticket', fn)       -> a refreshed ticket is ready (servers)
 *       t.on('peer', fn)         -> a peer connected (addresses, relay)
 *       await t.close()
 *
 * Deliberate properties:
 *   always encrypted — QUIC is TLS 1.3; there is no plaintext mode.
 *   keys are iroh tickets (`endpoint…`), not hs:// keys — a different network,
 *     so a holesail key and an iroh ticket can never talk to each other.
 *   a fixed `key` derives a deterministic identity (sha256 -> ed25519 seed),
 *     so a permanent tunnel keeps its address across restarts.
 *   UDP rides native QUIC datagrams, one flow per local source address (see
 *     DatagramStream): MTU-bounded, and an oversized datagram is DROPPED and
 *     counted rather than silently truncated.
 */

'use strict'

const crypto = require('crypto')
const net = require('net')
const dgram = require('dgram')
const { Duplex } = require('stream')
const { EventEmitter } = require('events')
const {
  Endpoint,
  EndpointAddr,
  EndpointId,
  EndpointTicket
} = require('@number0/iroh')

// One ALPN for tunnel traffic, one for the reachability probe. Separate
// ALPNs are what let `lookup` prove a peer is up WITHOUT opening a
// connection to its local service (the probe is accepted and closed).
const ALPN = Array.from(Buffer.from('iroh-tunnel/1'))
const PROBE_ALPN = Array.from(Buffer.from('iroh-tunnel/probe'))
// UDP tunnels get their own ALPN: a datagram flow has no bi-stream to carry a
// handshake, so the ALPN split is what stops a TCP client from being accepted
// by a UDP server (and vice versa) instead of failing somewhere mid-transfer.
const ALPN_UDP = Array.from(Buffer.from('iroh-tunnel/udp1'))
const CHUNK = 64 * 1024
const PROBE_MS = 12000

// A QUIC bi-stream is invisible to the peer until a frame is sent on it, so an
// opened-but-silent stream never fires the peer's acceptBi: a client whose app
// connection only RECEIVES (a download-only socket) would hang forever waiting
// for a tunnel the server never learns about. The opener therefore announces
// the stream, and the accepter consumes and verifies the token — iroh's own
// TCP forwarder does exactly this (dumbpipe's `HANDSHAKE = b"hello"`). The
// token here IS the ALPN, so a peer speaking a different protocol version is
// is refused instead of guessed at.
const HANDSHAKE = ALPN

// via runtime.js like every worker module: Bare has no global `process` (and
// this engine is Node-only anyway — napi prebuilds cannot load under Bare).
// Node-only project: no runtime shim. (holesail-gui read this from
// runtime.js because Bare has no global `process`.)
const proc = process

const dbg = (...a) => {
  if (proc.env && proc.env.IROH_DEBUG) console.error('[iroh:dbg]', ...a)
}
const toBuf = (x) => (Buffer.isBuffer(x) ? x : Buffer.from(x))
const sha256 = (s) => Array.from(crypto.createHash('sha256').update(s).digest())

/// Accept `iroh://<ticket>`, a bare ticket, or a bare endpoint id. Throws
/// 'Invalid key format' (the message the renderer already maps) for anything
/// else — a typo must not silently dial a different peer.
const sameAlpn = (a, b) =>
  Array.isArray(a) && a.length === b.length && a.every((x, i) => x === b[i])

function peerAddrFrom(key) {
  const raw = String(key || '')
    .trim()
    .replace(/^iroh:\/\//, '')
    .replace(/\/+$/, '')
  if (!raw) throw new Error('Connection string is required')
  try {
    return EndpointTicket.fromString(raw).endpointAddr()
  } catch {}
  try {
    return new EndpointAddr(EndpointId.fromString(raw), null, [])
  } catch {}
  throw new Error(
    `Invalid key format: ${raw.length} chars, expected an iroh ticket or endpoint id`
  )
}

function withTimeout(promise, ms, what) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`${what} timed out`)), ms).unref()
    )
  ])
}

/* --------------------------- the tunnel stream --------------------------- */
/* A QUIC bi-stream as a Node Duplex, oriented from the LOCAL SERVICE's
 * perspective: readable = what came from the peer (bytesDown), writable =
 * what goes to the peer (bytesUp). That is exactly the orientation stats.js
 * assumes when it wraps this object with ('bytesUp','bytesDown').
 *
 * Backpressure is real in both directions: the readable side only pulls from
 * the stream when the socket wants bytes (so a slow app throttles the peer
 * through QUIC flow control instead of buffering in this process), and the
 * writable side waits for `send.write()` to resolve.
 * `relay`/`rawStream` are read by stats.js to report session:peer routing. */
class TunnelStream extends Duplex {
  constructor(bi, info = {}) {
    super({ highWaterMark: 1 << 20 })
    this.bi = bi
    this.relay = info.relay || null
    this.rawStream = { remoteHost: info.peer || '' }
    this._pulling = false
  }

  _read() {
    if (this._pulling) return
    this._pulling = true
    this._pump()
  }

  async _pump() {
    try {
      for (;;) {
        const chunk = await this.bi.recv.read(CHUNK)
        if (!chunk || chunk.length === 0) break // EOF from the peer
        if (!this.push(toBuf(chunk))) {
          this._pulling = false // consumer will call _read() again
          return
        }
      }
      this._pulling = false
      this.push(null)
    } catch (err) {
      this._pulling = false
      this.destroy(err)
    }
  }

  _write(chunk, _enc, cb) {
    this._writeAll(toBuf(chunk)).then(
      () => cb(),
      (err) => cb(err)
    )
  }

  async _writeAll(buf) {
    let off = 0
    while (off < buf.length) {
      // iroh-ffi's SendStream::write takes a `Vec<u8>`, which the binding only
      // decodes from a plain JS Array — Buffer/Uint8Array raise "Failed to
      // get Array length". That per-chunk Array.from is this engine's
      // throughput ceiling. ponytail: accept it; the fix is upstream
      // (typed-array support in iroh-ffi), not a hand-rolled C shim here.
      const slice = buf.subarray(off, off + CHUNK)
      const n = await this.bi.send.write(Array.from(slice))
      if (!n || n < 0) throw new Error('tunnel stream closed')
      off += n
    }
  }

  _final(cb) {
    this.bi.send.finish().then(
      () => cb(),
      () => cb() // the peer may already be gone; not an error worth surfacing
    )
  }

  _destroy(err, cb) {
    // A clean end (session close, local socket closed) finishes the stream so
    // the peer sees EOF; only an ABNORMAL end resets it. Resetting on the
    // normal path makes every orderly teardown surface as a peer error.
    Promise.resolve()
      .then(() => (err ? this.bi.send.reset(0n) : this.bi.send.finish()))
      .catch(() => {})
      .then(() => this.bi.recv.stop(0n))
      .catch(() => {})
      .then(() => cb(err))
  }
}

/* A QUIC datagram flow as a Node Duplex, oriented exactly like TunnelStream
 * (readable = from the peer, writable = to the peer) so stats.js counts and
 * caps it with the same wrapper. Datagrams arrive through the engine's
 * readDatagram loop (pushDatagram) and leave through sendDatagram, which
 * resolves when the sender's buffer has room — datagrams are not retransmitted,
 * which is what UDP wants. iroh carries UDP natively, so there is no framing
 * step and no head-of-line blocking. */
class DatagramStream extends Duplex {
  constructor(conn, info = {}, engine = null) {
    super({ highWaterMark: 1 << 20 })
    this.conn = conn
    this.engine = engine
    this.relay = info.relay || null
    this.rawStream = { remoteHost: info.peer || '' }
  }

  pushDatagram(u8) {
    if (!this.destroyed) this.push(toBuf(u8))
  }

  _read() {}

  _write(chunk, _enc, cb) {
    const buf = toBuf(chunk)
    const max = this.conn.maxDatagramSize()
    if (max && buf.length > max) {
      // QUIC datagrams are MTU-bounded. holesail frames UDP over a stream, so it
      // has no MTU bound — but it truncates at 2 KB in some environments and not
      // others, silently either way, and being *told* beats that: drop this, and
      // let rejectCnt make it visible.
      // ponytail: drop and count — fragmenting would change what the receiving
      // app sees.
      if (this.engine) this.engine.stats.rejectCnt++
      cb()
      return
    }
    Promise.resolve()
      .then(() => this.conn.sendDatagramWait(Array.from(buf)))
      .then(
        () => cb(),
        () => cb() // a dropped datagram is normal for UDP
      )
  }

  _destroy(_err, cb) {
    cb()
  }
}

/* --------------------------------- engine -------------------------------- */

class Tunnel extends EventEmitter {
  constructor(opts = {}) {
    super()
    this.udp = !!opts.udp
    this.server = !!opts.server
    this.type = this.server ? 'server' : 'client'
    this.port = Number(opts.port)
    this.host = opts.host || '127.0.0.1'
    // normalise once: `iroh://<ticket>` with the prefix and any trailing
    // slash the UI/URL-parser added stripped off (that slash used to derive a
    // WRONG peer in holesail — same trap here)
    this.keyInput = opts.key
      ? String(opts.key)
          .trim()
          .replace(/^iroh:\/\//, '')
          .replace(/\/+$/, '')
      : null
    this.paused = false
    this.closed = false
    // engine-maintained counters, read by stats.js/limiter.js via
    // entries[i].stats (bytes* are added by the stats.js wrappers)
    this.stats = { bytesUp: 0, bytesDown: 0, locCnt: 0, rejectCnt: 0 }
    this.duplexes = new Set()
    this.sockets = new Set()
    this.conns = new Set()
    // `dht` is the holesail-shaped hole the rest of the worker reaches into
    this.dht = { stats: this.stats }
  }

  get info() {
    return {
      type: this.type,
      protocol: this.udp ? 'udp' : 'tcp',
      secure: true,
      port: this.port,
      host: this.host,
      url: this.url,
      // the string this tunnel is NAMED by: the key the user supplied
      // (identity seed) when there is one, else the generated ticket. The
      // saved-tunnel UI matches a saved entry to its running session on this,
      // so it must be the seed for permanent tunnels — the ticket is in `url`
      // and changes as the peer's addresses change.
      key: this.keyInput || this.ticket || this.publicKey,
      publicKey: this.publicKey
    }
  }

  async ready() {
    const ep = await Endpoint.bind({
      secretKey: this.keyInput ? sha256(this.keyInput) : undefined,
      alpns: [this.udp ? ALPN_UDP : ALPN, PROBE_ALPN]
    })
    this.ep = ep
    this.publicKey = ep.id().toString()
    this._setTicket()
    this._acceptLoop()
    if (this.server) this.dht.server = new EventEmitter()
    else await this._startProxy()
    this._refreshTicketWhenOnline()
    return this
  }

  /// A SERVER advertises its own ticket as the connection string. A CLIENT
  /// advertises the ticket it dialed (that is the string the user pasted and
  /// the one the UI shows on the card) — its own endpoint address is of no
  /// interest to anyone.
  _setTicket() {
    try {
      this.ticket = EndpointTicket.fromAddr(this.ep.addr()).toString()
    } catch {
      this.ticket = null
    }
    this.url = 'iroh://' + (this.server ? this.ticket : this.keyInput)
  }

  /// Prefer a ticket that includes the home relay: a ticket minted in the
  /// first seconds after bind may carry only LAN addresses, which nobody
  /// outside the network can dial. Refresh once the relay is up and tell the
  /// UI the new url (the old one keeps working for direct peers).
  _refreshTicketWhenOnline() {
    if (!this.server) return
    const before = this.ticket
    this.ep
      .online()
      .then(() => {
        if (this.closed) return
        this._setTicket()
        if (this.ticket && this.ticket !== before) {
          // servers: a refreshed ticket. Consumers that need to persist it
          // (the GUI wrote it to the event log) subscribe here.
          this.emit('ticket', {
            url: this.url,
            ticket: this.ticket,
            key: this.keyInput || this.ticket
          })
        }
      })
      .catch(() => {})
  }

  /* ------------------------------- server ------------------------------- */

  async _acceptLoop() {
    for (;;) {
      let incoming
      try {
        incoming = await this.ep.acceptNext()
      } catch {
        return
      }
      if (!incoming || this.closed) return
      // no await: connections are concurrent, one slow service must not block
      // the accept loop
      this._onIncoming(incoming)
    }
  }

  async _onIncoming(incoming) {
    try {
      if (this.paused) {
        this.stats.rejectCnt++
        await incoming.refuse()
        return
      }
      // order matters in this API: remoteAddr() is only readable while the
      // Incoming is unconsumed, alpn() only on the accepting handle
      const remote = await incoming.remoteAddr()
      const relay = remote.kind === 'relay' ? remote.addr || 'relay' : null
      const peer = remote.addr || remote.endpointId || ''
      const accepting = await incoming.accept()
      const alpn = await accepting.alpn()
      dbg(
        'incoming',
        JSON.stringify(peer),
        sameAlpn(alpn, PROBE_ALPN) ? 'probe' : 'tunnel'
      )
      if (sameAlpn(alpn, PROBE_ALPN)) {
        // Reachability probe: complete the handshake and hang up. Never
        // reaches the local service, so a lookup() leaves no trace as a
        // phantom connection in the owner's session:peer log. A probe is
        // deliberately hit-and-run — the caller closes the moment its
        // connect() resolves — so a failed connect() here is the normal
        // outcome ("timed out") and must not be reported as an incoming
        // failure: that spammed the app's event log on every reachability
        // check.
        try {
          const probeConn = await accepting.connect()
          probeConn.close(0n, [])
        } catch {}
        return
      }
      const conn = await accepting.connect()
      dbg('tunnel connection accepted', conn.remoteId().fmtShort())
      this.conns.add(conn)
      conn.closed().then(
        () => this.conns.delete(conn),
        () => this.conns.delete(conn)
      )
      if (this.udp) {
        // Datagram flow: no bi-stream and no handshake to read — the separate
        // UDP ALPN already proved the peer speaks this tunnel's protocol.
        this._serveUdp(conn, { relay, peer })
        return
      }
      for (;;) {
        let bi
        try {
          bi = await conn.acceptBi()
        } catch {
          break // the connection closed — normal end of this peer, not an error
        }
        if (this.paused) {
          this.stats.rejectCnt++
          bi.send.reset(0n).catch(() => {})
          continue
        }
        dbg('bi-stream -> local service', peer)
        this._serve(bi, { relay, peer })
      }
    } catch (err) {
      // connection closed / refused — the loop above ends on throw, so this
      // only guards the setup of a single connection. Never silent: a dropped
      // Incoming shows up on the peer as "server refused", and a P2P engine
      // with no diagnostics is undebuggable.
      console.error('[iroh] incoming failed:', err && err.message)
      this.stats.rejectCnt++
    }
  }

  /// Register a duplex for teardown. Every path that creates one — server TCP,
  /// server UDP, client TCP, client UDP flow — goes through here, so there is
  /// one place that knows what a live tunnel stream is.
  _track(duplex) {
    this.duplexes.add(duplex)
    duplex.on('close', () => this.duplexes.delete(duplex))
    return duplex
  }

  /// One tunnel connection -> one local service socket. Emitting 'connection'
  /// BEFORE piping is what lets stats.js wrap this exact duplex object
  /// (synchronously) and have every byte counted from the first one.
  async _serve(bi, info) {
    try {
      const hello = await bi.recv.readExact(HANDSHAKE.length)
      if (!sameAlpn(hello, HANDSHAKE)) throw new Error('bad handshake')
    } catch {
      this.stats.rejectCnt++ // peer vanished or speaks another version
      await bi.send.reset(0n).catch(() => {})
      return
    }
    const duplex = this._track(new TunnelStream(bi, info))
    duplex.on('close', () => {
      this.stats.locCnt = Math.max(0, this.stats.locCnt - 1)
    })
    this.dht.server.emit('connection', duplex)
    const sock = net.connect(this.port, this.host)
    this.sockets.add(sock)
    this.stats.locCnt++
    this._pair(duplex, sock)
  }

  /// Bridge a tunnel duplex and a local socket. Every failure path here ends
  /// ONE connection: a socket error destroys the duplex, a tunnel error
  /// destroys the socket — and the tunnel error is heard (an unhandled
  /// 'error' event on a stream takes the whole worker down, which for a P2P
  /// engine is the difference between one dropped game server and 12).
  _pair(duplex, sock) {
    duplex.on('error', (err) => {
      // expected when we dropped the connection ourselves (pause/close) or when
      // the PEER closed cleanly: QUIC reports a normal shutdown as
      // ConnectionLost(ApplicationClosed(ApplicationClose { error_code: 0 }))
      // — a stop, not a fault, and the user's event log should not cry error
      // every time they hit Stop. Unrecognised shapes still log: this only
      // silences the clean case, so a real fault can never disappear here.
      const msg = String((err && err.message) || err)
      const clean =
        /ApplicationClosed\(ApplicationClose \{ error_code: 0\b/.test(msg) ||
        /^Reset\(0\)$/.test(msg) || // peer stopped the stream = app cancelled
        msg.includes('LocallyClosed') ||
        /\b(ECONNRESET|EPIPE)\b/.test(msg) // local app hung up mid-request
      if (!this.paused && !this.closed && !clean)
        console.error('[iroh] tunnel error:', msg)
      sock.destroy()
    })
    // Forward the socket error itself, errno included: it is what tells a
    // cancelled request (ECONNRESET, benign, not logged) from a service that
    // is not listening (ECONNREFUSED, a fault worth a line).
    sock.on('error', (err) => duplex.destroy(err))
    // Deliberately NO destroy on socket 'close'. pipe() already ends the
    // duplex when the socket's write side finishes, and that end goes through
    // the limiter's deferred end (queueEnd) — so it lands AFTER the capped
    // backlog is flushed. Destroying here instead FINs the stream with the
    // tail still queued: a 512 KB transfer arrived as 485376 bytes, the
    // remainder silently discarded, with the peer reading a clean EOF.
    sock.pipe(duplex)
    duplex.pipe(sock)
  }

  /// A UDP tunnel connection: one local UDP socket per peer flow — exactly
  /// the topology holesail uses (a framed pipe per connection) — so a service
  /// that keys sessions by source port behaves the same. The socket's family
  /// follows the service host.
  _serveUdp(conn, info) {
    const sock = dgram.createSocket(this.host.includes(':') ? 'udp6' : 'udp4')
    const stream = this._track(new DatagramStream(conn, info, this))
    // Emitted BEFORE anything flows: stats.js wraps this exact object
    // synchronously ('data' = from the peer, write = to the peer), so the
    // session's counters and the per-session cap mean the same thing here as
    // they do for TCP.
    this.dht.server.emit('connection', stream)
    stream.on('data', (d) => {
      sock.send(d, this.port, this.host, (err) => {
        if (err && !this.paused) this.stats.rejectCnt++
      })
    })
    sock.on('message', (msg) => {
      if (!this.paused) stream.write(msg)
    })
    sock.on('error', () => stream.destroy())
    stream.on('close', () => {
      try {
        sock.close()
      } catch {}
    })
    ;(async () => {
      for (;;) {
        let d
        try {
          d = await conn.readDatagram()
        } catch {
          break // connection gone
        }
        if (this.paused) continue // paused drops instead of queueing
        stream.pushDatagram(d)
      }
    })().catch(() => {})
  }

  /* ------------------------------- client ------------------------------- */

  async _startProxy() {
    if (this.udp) return this._startUdpProxy()
    const srv = net.createServer((sock) => this._onLocal(sock))
    this.dht.proxy = srv
    await new Promise((resolve, reject) => {
      srv.once('error', reject)
      srv.listen(this.port, this.host, resolve)
    })
    this.port = srv.address().port // the OS may have reassigned it
    this._peer = peerAddrFrom(this.keyInput)
  }

  /// UDP client: a local UDP socket (the `proxySocket` stats.js counts, the
  /// same field holesail exposes) plus ONE tunnel connection per distinct
  /// local source address — the topology createUdpFramedProxy uses, so a
  /// service that keys sessions by source port sees the same thing.
  async _startUdpProxy() {
    const sock = dgram.createSocket(this.host.includes(':') ? 'udp6' : 'udp4')
    this.dht.proxySocket = sock
    await new Promise((resolve, reject) => {
      sock.once('error', reject)
      sock.bind(this.port, this.host, resolve)
    })
    this.port = sock.address().port
    this._peer = peerAddrFrom(this.keyInput)
    this.udpFlows = new Map() // local `addr:port` -> { conn, stream, rinfo }
    this.udpPending = new Set() // sources whose first connection is dialing
    sock.on('message', (msg, rinfo) => this._onLocalDatagram(msg, rinfo))
  }

  /// UDP is allowed to lose packets: while paused (or overloaded) a datagram
  /// is dropped, never queued. A flow that cannot be established is forgotten
  /// so the next datagram retries it.
  async _onLocalDatagram(msg, rinfo) {
    if (this.paused || this.closed) return
    const key = `${rinfo.address}:${rinfo.port}`
    let flow = this.udpFlows.get(key)
    if (!flow) {
      if (this.udpPending.has(key)) return // dialing: drop (UDP may lose)
      this.udpPending.add(key)
      try {
        flow = await this._openUdpFlow(key, rinfo)
        this.udpFlows.set(key, flow)
      } catch {
        this.stats.rejectCnt++
        return
      } finally {
        this.udpPending.delete(key)
      }
    }
    if (!flow.stream.destroyed) flow.stream.write(msg)
  }

  /// ponytail: flows live for the session's lifetime — no idle reaping, since
  /// only processes on this host can open a local source address on a
  /// loopback-bound socket.
  async _openUdpFlow(key, rinfo) {
    const conn = await this.ep.connect(this._peer, ALPN_UDP)
    const stream = this._track(
      new DatagramStream(conn, { peer: rinfo.address }, this)
    )
    const flow = { conn, stream, rinfo }
    // A dead flow is FORGOTTEN, not kept: the next datagram from that source
    // re-dials. Keeping a dead entry would silently black-hole the source.
    const forget = () => {
      this.conns.delete(conn)
      this.duplexes.delete(stream)
      if (this.udpFlows.get(key) === flow) this.udpFlows.delete(key)
    }
    this.conns.add(conn)
    conn.closed().then(forget, forget)
    stream.on('data', (d) => {
      // answers go back to the exact source that opened this flow
      this.dht.proxySocket.send(d, rinfo.port, rinfo.address, (err) => {
        if (err) this.stats.rejectCnt++
      })
    })
    ;(async () => {
      for (;;) {
        let d
        try {
          d = await conn.readDatagram()
        } catch {
          break // connection gone
        }
        if (this.paused) continue
        stream.pushDatagram(d)
      }
    })().catch(() => {})
    return flow
  }

  async _onLocal(sock) {
    // Pause NOW, before the first await. stats.js attaches a byte-counting
    // 'data' listener to this socket as soon as it appears, which puts the
    // socket in flowing mode — every byte the app sends during the dial below
    // would be handed to that counter and dropped, because nothing is piping
    // it yet (observed as an HTTP request that never arrives: the client's
    // stream opens, the tunnel stays silent, the caller hangs). Paused, those
    // bytes buffer until _pair() pipes the socket, and pipe() resumes it.
    sock.pause()
    if (this.paused || this.closed) {
      this.stats.rejectCnt++
      sock.destroy()
      return
    }
    this.sockets.add(sock)
    this.stats.locCnt++
    sock.on('close', () => {
      this.sockets.delete(sock)
      this.stats.locCnt = Math.max(0, this.stats.locCnt - 1)
    })
    try {
      const conn = await this._tunnelConn()
      const bi = await conn.openBi()
      // announce the stream before piping anything into it (see HANDSHAKE)
      await bi.send.write(HANDSHAKE)
      const duplex = this._track(new TunnelStream(bi))
      duplex.conn = conn
      const selected = conn.paths().find((p) => p.isSelected)
      duplex.relay = selected && selected.isRelay ? 'relay' : null
      duplex.rawStream = { remoteHost: conn.remoteId().toString() }
      this._pair(duplex, sock)
    } catch (err) {
      // peer unreachable / key wrong: this local connection dies, the session
      // (and every other local connection on it) stays up
      console.error('[iroh] client dial failed:', err && err.message)
      this.stats.rejectCnt++
      sock.destroy()
    }
  }

  /// One QUIC connection per session, re-dialed after it drops: the tunnel is
  /// a transport, not a per-socket thing (each local socket gets its own
  /// bi-stream). One shared connection, measured rather than assumed: 20
  /// simultaneous local sockets were served over it in ~90 ms (holesail needs
  /// ~180 ms of DHT setup PER socket), so a per-socket dial buys nothing.
  /// `setMaxConcurrentBiStreams` was left at its default for the same reason —
  /// no blocking at 20 concurrent streams.
  async _tunnelConn() {
    if (this._conn && !this._connClosed) return this._conn
    if (!this._dialing) {
      this._dialing = this.ep.connect(this._peer, ALPN)
      this._dialing.catch(() => {
        this._dialing = null
      })
    }
    const conn = await this._dialing
    if (!this._conn || this._connClosed) {
      this._conn = conn
      this._connClosed = false
      this._dialing = null
      const lost = () => {
        this._connClosed = true
        if (this._conn === conn) this._conn = null
        // The connection carries every stream of this tunnel: when it dies
        // they are all dead, and a QUIC stream parked in read() does NOT
        // wake up on its own (measured: a SIGKILLed peer left the app's
        // sockets hanging with nothing logged, session still "running").
        // Fail them so the app sees a reset and retries — the session itself
        // survives and the next local connection re-dials.
        for (const d of this.duplexes) {
          if (d.conn === conn && !d.destroyed)
            d.destroy(new Error('tunnel connection lost'))
        }
      }
      conn.closed().then(lost, lost)
    }
    return this._conn
  }

  /* ------------------------------ lifecycle ----------------------------- */

  async pause() {
    this.paused = true
    this.stats.rejectCnt += this.duplexes.size // connections we are about to drop
    this._dropActive()
  }

  async resume() {
    this.paused = false
  }

  _dropActive() {
    dbg('dropActive', this.duplexes.size, 'streams,', this.conns.size, 'conns')
    for (const d of [...this.duplexes]) {
      try {
        d.destroy()
      } catch {}
    }
    for (const s of [...this.sockets]) {
      try {
        s.destroy()
      } catch {}
    }
    for (const c of [...this.conns]) {
      try {
        c.close(0n, [])
      } catch {}
    }
  }

  async close() {
    if (this.closed) return
    this.closed = true
    this._dropActive()
    if (this.dht.proxy) await new Promise((res) => this.dht.proxy.close(res))
    if (this.dht.proxySocket) {
      try {
        this.dht.proxySocket.close()
      } catch {}
    }
    await this.ep.close().catch(() => {})
  }
}

/// Reachability preflight for the `lookup` RPC: dial with the probe ALPN and
/// hang up. Unlike holesail's DHT-record read this proves the peer is
/// actually reachable, and it never touches the peer's local service — a
/// phantom connection in the owner's event log was the alternative.
async function lookup(key) {
  const addr = peerAddrFrom(key)
  const ep = await Endpoint.bind({ alpns: [ALPN, PROBE_ALPN] })
  try {
    const conn = await withTimeout(
      ep.connect(addr, PROBE_ALPN),
      PROBE_MS,
      'lookup'
    )
    conn.close(0n, [])
    return {
      protocol: 'tcp',
      secure: true,
      endpointId: addr.id().toString(),
      addrs: addr.directAddresses(),
      relayUrl: addr.relayUrl()
    }
  } catch {
    return null
  } finally {
    await ep.close().catch(() => {})
  }
}

module.exports = { Tunnel, lookup }
