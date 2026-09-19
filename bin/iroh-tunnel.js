#!/usr/bin/env node
/* iroh-tunnel CLI — publish a local port, or dial someone else's tunnel.
 *
 *   iroh-tunnel share 8080 [--udp] [--key <ticket>]
 *   iroh-tunnel connect <ticket> --port 9090 [--udp]
 *
 * The tunnel is always encrypted (QUIC/TLS 1.3) and the ticket is what grants
 * access: anyone holding it can reach the port you published. Treat it as a
 * secret; the connection is peer-to-peer, with relay fallback when a direct
 * path cannot be punched.
 */

'use strict'

const { Tunnel } = require('../src/index.js')

function usage(code) {
  console.error(`usage:
  iroh-tunnel share <port> [--udp] [--key <ticket>]
  iroh-tunnel connect <ticket> --port <localPort> [--udp]`)
  process.exit(code)
}

const [cmd, arg, ...rest] = process.argv.slice(2)
if (!cmd || !arg) usage(2)

const flagValue = (name) => {
  const i = rest.indexOf(`--${name}`)
  return i >= 0 ? rest[i + 1] : undefined
}
const udp = rest.includes('--udp')

async function main() {
  if (cmd === 'share') {
    const port = Number(arg)
    if (!Number.isInteger(port) || port < 1 || port > 65535) usage(2)
    const t = new Tunnel({ server: true, port, udp, key: flagValue('key') })
    await t.ready()
    console.log(`listening 127.0.0.1:${port}${udp ? ' (udp)' : ''}`)
    console.log(`ticket: ${t.ticket || t.url}`)
    // a fixed key can resolve to a different address once the endpoint is
    // online; consumers persisting the ticket need to know it changed
    t.on('ticket', (e) => console.log(`ticket updated: ${e.ticket}`))
    return
  }

  if (cmd === 'connect') {
    const port = Number(flagValue('port'))
    if (!Number.isInteger(port) || port < 1 || port > 65535) usage(2)
    const t = new Tunnel({ client: true, key: arg, udp, port })
    await t.ready()
    console.log(`127.0.0.1:${port} -> tunnel${udp ? ' (udp)' : ''}`)
    return
  }

  usage(2)
}

main().catch((err) => {
  console.error(String((err && err.message) || err))
  process.exit(1)
})
