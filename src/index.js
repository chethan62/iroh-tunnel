/* iroh-tunnel — a TCP/UDP tunnel over iroh.
 *
 * Extracted from holesail-gui (github.com/chethan62/holesail-gui), where this
 * was an opt-in second engine behind that app's worker facade. It became its
 * own project because it can never share the GUI's runtime: @number0/iroh
 * ships NAPI-RS prebuilds requiring Node >= 20.3, and the GUI's packaged
 * builds run their worker under Bare (its own addon ABI), so the engine could
 * never ship there.
 *
 *   const { Tunnel, lookup } = require('iroh-tunnel')
 *
 * MIT — see LICENSE. The iroh dependency is MIT/Apache-2.0.
 */

'use strict'

module.exports = require('./tunnel.js')
