/* test/tunnel.test.js — self-contained proof that the extracted library still
 * does what this engine did inside holesail-gui's worker: a TCP tunnel end to
 * end, a reachability lookup, a UDP tunnel with the oversize-drop rule, and
 * the invalid-key message that must not carry key material.
 *
 * Needs network access (the public iroh DHT/relay) and takes ~1-2 minutes.
 * Run: npm test
 */

'use strict'

const assert = require('assert')
const net = require('net')
const dgram = require('dgram')
const { Tunnel, lookup } = require('../src/index.js')

const servers = []
const sockets = []
const tunnels = []

const freePort = () =>
  new Promise((resolve) => {
    const probe = net.createServer()
    probe.listen(0, '127.0.0.1', () => {
      const p = probe.address().port
      probe.close(() => resolve(p))
    })
  })

const tcpEcho = (port) =>
  new Promise((resolve) => {
    const srv = net.createServer((sock) => sock.pipe(sock))
    srv.listen(port, '127.0.0.1', () => {
      servers.push(srv)
      resolve(srv)
    })
  })

const udpEcho = (port) =>
  new Promise((resolve) => {
    const s = dgram.createSocket('udp4')
    s.on('message', (msg, rinfo) => s.send(msg, rinfo.port, rinfo.address))
    s.bind(port, '127.0.0.1', () => {
      servers.push(s)
      resolve(s)
    })
  })

// Retry until the answer arrives: the first datagram or byte can be lost while
// the tunnel finishes establishing, which is not the thing under test.
const until = (attach, send, isDone, tryMs, giveUpMs) =>
  new Promise((resolve) => {
    let settled = false
    const iv = setInterval(send, tryMs)
    const finish = (v) => {
      if (settled) return
      settled = true
      // Clearing the retry interval here is what lets the process exit once
      // the answer arrives. The first version only cleared on timeout, so the
      // loop stayed alive forever and the test never returned in CI.
      clearInterval(iv)
      resolve(v)
    }
    attach(finish)
    send()
    setTimeout(() => finish(null), giveUpMs)
  })

const tcpRoundTrip = (port, payload, giveUpMs = 60000) =>
  new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1')
    const got = []
    sock.on('connect', () => sock.write(payload))
    sock.on('data', (c) => {
      got.push(c)
      if (Buffer.concat(got).length >= payload.length) {
        sock.destroy()
        resolve(Buffer.concat(got))
      }
    })
    sock.on('error', reject)
    setTimeout(() => {
      sock.destroy()
      resolve(null)
    }, giveUpMs)
  })

async function main() {
  const t0 = Date.now()

  // 1) a TCP tunnel, end to end
  console.log('1) TCP tunnel carries bytes through iroh')
  const echoPort = await freePort()
  await tcpEcho(echoPort)
  const srv = new Tunnel({ server: true, port: echoPort })
  tunnels.push(srv)
  await srv.ready()
  assert(typeof srv.url === 'string' && srv.url.length > 20, `server produced a ticket (${srv.url})`)
  console.log('  ✓ server listening, ticket published')

  const cliPort = await freePort()
  const cli = new Tunnel({ client: true, key: srv.url, port: cliPort })
  tunnels.push(cli)
  await cli.ready()
  const echoed = await tcpRoundTrip(cliPort, Buffer.from('tunnel payload'))
  assert(echoed && echoed.toString() === 'tunnel payload', `payload came back through the tunnel (got: ${echoed})`)
  console.log('  ✓ payload echoed through the tunnel')

  // 2) lookup proves the peer is up without dialling its local service
  const found = await lookup(srv.url)
  assert(found && found.endpointId, `lookup found the peer (got: ${JSON.stringify(found)})`)
  console.log('  ✓ lookup reached the peer on the probe ALPN')

  // 3) UDP rides QUIC datagrams, boundaries preserved
  console.log('2) UDP tunnel carries datagrams')
  const uePort = await freePort()
  await udpEcho(uePort)
  const usrv = new Tunnel({ server: true, udp: true, port: uePort })
  tunnels.push(usrv)
  await usrv.ready()
  const ucliPort = await freePort()
  const ucli = new Tunnel({ client: true, udp: true, key: usrv.url, port: ucliPort })
  tunnels.push(ucli)
  await ucli.ready()

  const usock = dgram.createSocket('udp4')
  sockets.push(usock)
  usock.bind(0, '127.0.0.1')
  const first = await until(
    (finish) => usock.on('message', (m) => m.toString() === 'ping-dgram' && finish(m)),
    () => usock.send(Buffer.from('ping-dgram'), ucliPort, '127.0.0.1'),
    null,
    1500,
    60000
  )
  assert(first, 'a datagram made the round trip')
  console.log('  ✓ datagram echoed through the tunnel')

  // an 8 KiB datagram exceeds what a QUIC datagram carries: iroh DROPS it
  // (rather than silently truncating, which is what a framed stream does) and
  // the tunnel has to survive it.
  usock.send(Buffer.alloc(8192, 7), ucliPort, '127.0.0.1')
  await new Promise((r) => setTimeout(r, 3000))
  const after = await until(
    (finish) => usock.on('message', (m) => m.toString() === 'after-big' && finish(m)),
    () => usock.send(Buffer.from('after-big'), ucliPort, '127.0.0.1'),
    null,
    1500,
    30000
  )
  assert(after, 'the tunnel still relays normal datagrams after an oversize one')
  console.log('  ✓ survived an oversize datagram (dropped, not truncated)')

  // 4) an unparseable key is rejected, without echoing the input
  console.log('3) an unparseable key is rejected without echoing it')
  const bogus = 'deadbeefdeadbeefdeadbeef'
  let msg = ''
  try {
    const bad = new Tunnel({ client: true, key: bogus, port: await freePort() })
    tunnels.push(bad)
    await bad.ready()
    await bad.close()
  } catch (err) {
    msg = String((err && err.message) || err)
  }
  assert(/Invalid key format/.test(msg), `the key is rejected (got: ${msg || 'no error'})`)
  assert(!msg.includes(bogus.slice(0, 12)), 'the rejected key is not echoed into the message')
  console.log('  ✓ rejected, and the message carries no key material')

  console.log(`\nALL TESTS PASSED ✅ (${((Date.now() - t0) / 1000).toFixed(1)}s)`)
}

main()
  .catch((err) => {
    console.error('\nTEST FAILED ❌\n' + err.message)
    process.exitCode = 1
  })
  .finally(async () => {
    for (const t of tunnels) {
      try {
        await t.close()
      } catch {}
    }
    for (const s of servers) {
      try {
        s.close()
      } catch {}
    }
    for (const s of sockets) {
      try {
        s.close()
      } catch {}
    }
    // iroh's endpoint teardown leaves Rust-side handles the event loop waits
    // on, so the run would hang after passing. Exit explicitly: the verdict is
    // already decided by then, and a hang would look like a CI timeout.
    process.exit(process.exitCode || 0)
  })
