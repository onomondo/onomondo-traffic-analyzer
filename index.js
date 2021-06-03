#!/usr/bin/env node

const pcapParser = require('pcap-parser')
const sessions = require('./sessions')
const prettyBytes = require('pretty-bytes')
const ipChecker = require('onomondo-ip-checker')
const minimist = require('minimist')
const { ipHeaderParser, tcpHeaderParser, udpHeaderParser, tlsHeaderParser } = require('./parsers')
const pkgJson = require('./package.json')
const getPackageJson = require('package-json')

const argv = minimist(process.argv.slice(2))
const pcapFilename = argv._.join(' ')
const packetType = argv.type || 'ip'
const hasCorrectPacketType = packetType === 'ip' || packetType === 'ethernet'
const hasAllParameters = packetType && pcapFilename

if (!pcapFilename) exit('You need to specify filename to pcap file')
if (!hasAllParameters) exit('Not all needed parameters are specified')
if (!hasCorrectPacketType) exit('Only "ip" and "ethernet" packet types are allowed')

const allTcpSessions = []
const trafficToHosts = {}
const erroneousPackets = []
const totals = {
  bytesCount: 0,
  packetsCount: 0,
  tcpBytesCount: 0,
  udpBytesCount: 0
}
const tcpRetransmission = {
  allPacketsBuffer: [],
  allPacketsByteCount: 0,
  allPacketsCount: 0,
  resentPacketsCount: 0,
  resentBytesCount: 0
}

run()

async function run () {
  console.error(`Onomondo Traffic Analyzer ${pkgJson.version} (node.js ${process.version})`)
  console.error('')

  const publicVersion = await getPublicVersion()
  const isUsingCorrectVersion = pkgJson.version === publicVersion
  if (!isUsingCorrectVersion) console.error(`You are currently using version ${pkgJson.version} and the latest version is ${publicVersion}\n`)

  pcapParser
    .parse(pcapFilename)
    .on('packet', packet => {
      try {
        parsePacket(packet)
      } catch (err) {
        erroneousPackets.push({
          number: totals.packetsCount,
          size: packet.data.length,
          error: err.message
        })
      }
    })
    .on('end', () => {
      sessions.tcp.getAll().forEach(tcpSession => allTcpSessions.push(tcpSession))
      console.log([
        '',
        '🌎 Overall information',
        '======================',
        `Total traffic: ${pretty(totals.bytesCount)}`,
        `TCP traffic:   ${pretty(totals.tcpBytesCount)} (${percentage(totals.tcpBytesCount, totals.bytesCount)}% of all traffic)`,
        `UDP traffic:   ${pretty(totals.udpBytesCount)} (${percentage(totals.udpBytesCount, totals.bytesCount)}% of all traffic)`,
        ''
      ].join('\n'))

      console.log([
        '',
        '👯‍♀️ TCP Retransmission information',
        '=================================',
        `Total TCP traffic:  ${pretty(tcpRetransmission.allPacketsByteCount)} (${tcpRetransmission.allPacketsCount} packets)`,
        `Resent TCP traffic: ${pretty(tcpRetransmission.resentBytesCount)} (${tcpRetransmission.resentPacketsCount} packets)`,
        `TCP retransmisisons count for ${percentage(tcpRetransmission.resentBytesCount, tcpRetransmission.allPacketsByteCount)}% of all TCP traffic`,
        '',
        'The TCP retransmission says something about how much TCP traffic is resent.',
        'It is not necesarrily a bad thing, but if the percentage is above ~15% you',
        'should probably look into why that it.',
        ''
      ].join('\n'))

      const tlsTotal = allTcpSessions.filter(({ type }) => type === 'tls').reduce((tlsTotal, { bytes }) => tlsTotal + bytes, 0)
      const tlsMeta = allTcpSessions.filter(({ type }) => type === 'tls').reduce((tlsMeta, { tls: { metaTraffic } }) => tlsMeta + metaTraffic, 0)
      console.log([
        '',
        '🔒 TLS Information',
        '==================',
        `Total traffic sent over TLS: ${pretty(tlsTotal)} (${percentage(tlsTotal, totals.bytesCount)}% of all traffic)`,
        `Meta traffic sent over TLS:  ${pretty(tlsMeta)} (${percentage(tlsMeta, totals.bytesCount)}% of all traffic [potential removal if using Connectors])`,
        '',
        'The meta traffic in TLS is mostly the handshake. If the meat traffic accounts',
        'for most of the traffic, then you could look into using Connectors and see if',
        'you can save any data.',
        ''
      ].join('\n'))

      console.log([
        '',
        '🚦 Hosts information',
        '====================',
      ].concat(Object
        .entries(trafficToHosts)
        .map(([ip, { bytesUp, bytesDown }]) =>
          `${strLen(ip, 15)} ${pretty(bytesUp)}⬆ ${pretty(bytesDown)}⬇  (${percentage(bytesUp + bytesDown, totals.bytesCount)}% of all traffic)`
      )).concat([
        '',
        'Information about hosts can be used to see if there is something that looks out',
        'of ordinary. And to give insights into which hosts account for most of the',
        'traffic.',
        ''
      ])
      .join('\n'))

      if (erroneousPackets.length) {
        const erroneousTotalSize = erroneousPackets.reduce((erroneousTotalSize, { size }) => erroneousTotalSize + size, 0)
        console.log([
          '',
          '🛑 Parsing error information',
          '============================',
          `Total size of erroneous packets: ${pretty(erroneousTotalSize)}`,
          'Erroneous packets:',
          erroneousPackets.map(({ number, error }) => `[${number}] ${error}`).join('\n'),
          '',
          'This is debugging information that can be shared with Onomondo. The Traffic',
          'Analyzer had issues parsing some packets. You can send this information as long',
          'as your PCAP file to Onomondo and we use this to make the Traffic Analyzer',
          'better.'
        ].join('\n'))
      }
    })
}

function parsePacket ({ header, data: packet }) {
  const ipPacket = packetType === 'ip'
    ? packet
    : packet.slice(14)
  const ipHeader = ipHeaderParser.parse(ipPacket)
  const isIcmp = ipHeader.protocol === 1
  const isTcp = ipHeader.protocol === 6
  const isUdp = ipHeader.protocol === 17
  const isFromDevice = ipChecker.isDeviceSubnet(ip(ipHeader.src))
  const trafficHost = isFromDevice ? ip(ipHeader.dst) : ip(ipHeader.src)
  trafficToHosts[trafficHost] = trafficToHosts[trafficHost] || { bytesUp: 0, bytesDown: 0 }
  if (isFromDevice) {
    trafficToHosts[trafficHost].bytesUp += packet.length
  } else {
    trafficToHosts[trafficHost].bytesDown += packet.length
  }

  totals.bytesCount += packet.length
  totals.packetsCount += 1

  if (isUdp) {
    const udpPacket = ipHeader.data
    const udpHeader = udpHeaderParser.parse(udpPacket)
    const currentSession = sessions.udp.get({ ipHeader, udpHeader }) || { packets: 0, bytes: 0 }

    totals.udpBytesCount += packet.length

    sessions.udp.set({
      ipHeader,
      udpHeader,
      value: {
        packets: currentSession.packets + 1,
        bytes: currentSession.bytes + packet.length
      }
    })
  }
  if (isTcp) {
    const tcpPacket = ipHeader.data
    const tcpHeader = tcpHeaderParser.parse(tcpPacket)
    const isFirst = tcpHeader.flags.syn && !tcpHeader.flags.ack
    const isTls = tcpHeader.srcPort === 443 || tcpHeader.srcPort === 8883 || tcpHeader.dstPort === 443 || tcpHeader.dstPort === 8883

    totals.tcpBytesCount += packet.length

    // Retransmission handling
    const tcpPacketHex = tcpPacket.toString('hex')
    const isPacketAlreadySent = tcpRetransmission.allPacketsBuffer.includes(tcpPacketHex)
    if (!isPacketAlreadySent) tcpRetransmission.allPacketsBuffer.push(tcpPacketHex)
    tcpRetransmission.allPacketsCount += 1
    tcpRetransmission.allPacketsByteCount += tcpPacket.length
    if (isPacketAlreadySent) {
      tcpRetransmission.resentBytesCount += tcpPacket.length
      tcpRetransmission.resentPacketsCount += 1
    }

    if (isFirst) {
      const currentSession = sessions.tcp.get({ ipHeader, tcpHeader })
      const tcpPortsAlreadyInUse = !!currentSession
      if (tcpPortsAlreadyInUse) {
        allTcpSessions.push(currentSession)
      }
      sessions.tcp.set({ ipHeader, tcpHeader, value: { packets: 0, bytes: 0 } })
    }

    const session = sessions.tcp.get({ ipHeader, tcpHeader }) || { packets: 0, bytes: 0 }

    if (isTls) {
      const tlsPacket = tcpHeader.data
      session.type = 'tls'
      session.tls = session.tls || { metaTraffic: 0 }

      if (tlsPacket.length !== 0) {
        // When retransmissions happen, a packet may contain only the first part of a TLS packet.
        // E.g. a packet could be 1360 bytes long, but in the TLS layer it can report that it's e.g 2500 bytes long.
        // So be to on the safe side, we only take the minimum of packet length or the tls' layers combined length.
        const tlsHeader = tlsHeaderParser.parse(tlsPacket)
        const bytesToSaveReportedFromTlsLayers = tlsHeader.layers.reduce((bytesToSave, { type, version, length }) => {
          const isHandshake = type === 22
          const isCipherChange = type === 20
          const isMetaTrafic = isHandshake || isCipherChange

          return bytesToSave + (isMetaTrafic ? length : 0)
        }, 0)
        const actualBytesToSave = Math.min(bytesToSaveReportedFromTlsLayers, ipPacket.length)
        session.tls.metaTraffic += actualBytesToSave
      }
    }

    session.packets += 1
    session.bytes += packet.length
    sessions.tcp.set({
      ipHeader,
      tcpHeader,
      value: session
    })
  }
}

function percentage (part, all) {
  return Math.floor(100 * (part / all))
}

function strLen (str, length, align = 'left') {
  if (align === 'left') return str + Array(length - str.length).fill(' ').join('')
  if (align === 'right') return Array(length - str.length).fill(' ').join('') + str
}

function pretty (bytes, length = 12, align = 'right') {
  return strLen(prettyBytes(bytes, { minimumFractionDigits: 2, maximumFractionDigits: 2 }), length, align)
}

function ip (buf) {
  return `${buf[0]}.${buf[1]}.${buf[2]}.${buf[3]}`
}

function exit (str) {
  console.log(str)
  console.log()
  console.log('See https://github.com/onomondo/onomondo-traffic-analyzer for more information')
  process.exit(1)
}

async function getPublicVersion () {
  const pkgJson = await getPackageJson('onomondo-traffic-analyzer')
  return pkgJson.version
}
