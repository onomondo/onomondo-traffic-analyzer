const pcapParser = require('pcap-parser')
const BinaryParser = require('binary-parser').Parser
const sessions = require('./sessions')
const pretty = require('pretty-bytes')
const ipChecker = require('onomondo-ip-checker')

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

const allTcpSessions = []
const trafficToHosts = {}

pcapParser
  .parse(process.argv[2])
  .on('packet', ({ header, data: ipPacket }) => {
    const ipHeader = ipHeaderParser.parse(ipPacket)
    const isIcmp = ipHeader.protocol === 1
    const isTcp = ipHeader.protocol === 6
    const isUdp = ipHeader.protocol === 17
    const isFromDevice = ipChecker.isDeviceSubnet(ip(ipHeader.src))
    const trafficHost = isFromDevice ? ip(ipHeader.dst) : ip(ipHeader.src)
    trafficToHosts[trafficHost] = trafficToHosts[trafficHost] || { bytesUp: 0, bytesDown: 0 }
    if (isFromDevice) {
      trafficToHosts[trafficHost].bytesUp += ipPacket.length
    } else {
      trafficToHosts[trafficHost].bytesDown += ipPacket.length
    }

    totals.bytesCount += ipPacket.length
    totals.packetsCount += 1

    if (isUdp) {
      const udpPacket = ipPacket.slice(20)
      const udpHeader = udpHeaderParser.parse(udpPacket)
      const currentSession = sessions.udp.get({ ipHeader, udpHeader }) || { packets: 0, bytes: 0 }

      totals.udpBytesCount += ipPacket.length

      sessions.udp.set({
        ipHeader,
        udpHeader,
        value: {
          packets: currentSession.packets + 1,
          bytes: currentSession.bytes + ipPacket.length
        }
      })
    }
    if (isTcp) {
      const tcpPacket = ipPacket.slice(20)
      const tcpHeader = tcpHeaderParser.parse(tcpPacket)
      const isFirst = tcpHeader.flags.syn && !tcpHeader.flags.ack
      const isTls = tcpHeader.srcPort === 443 || tcpHeader.srcPort === 8883 || tcpHeader.dstPort === 443 || tcpHeader.dstPort === 8883

      totals.tcpBytesCount += ipPacket.length

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
        // If srcIp:srcPort <-> dstIp:dstPort is reused, then
        const currentSession = sessions.tcp.get({ ipHeader, tcpHeader })
        const tcpPortsAlreadyInUse = !!currentSession
        if (tcpPortsAlreadyInUse) {
          allTcpSessions.push(currentSession)
        }
        sessions.tcp.set({ ipHeader, tcpHeader, value: { packets: 0, bytes: 0 } })
      }

      const session = sessions.tcp.get({ ipHeader, tcpHeader }) || { packets: 0, bytes: 0 }

      if (isTls) {
        const tlsPacket = ipPacket.slice(8 * tcpHeader.dataOffset)
        session.type = 'tls'
        session.tls = session.tls || { metaTraffic: 0 }

        if (tlsPacket.length !== 0) {
          const tlsHeader = tlsHeaderParser.parse(tlsPacket)
          const isHandshake = tlsHeader.type === 22
          const isCipherChange = tlsHeader.type === 20
          const isMetaTrafic = isHandshake || isCipherChange
          if (isMetaTrafic) session.tls.metaTraffic += tlsHeader.length
        }
      }

      session.packets += 1
      session.bytes += ipPacket.length
      sessions.tcp.set({
        ipHeader,
        tcpHeader,
        value: session
      })
    }
  })
  .on('end', () => {
    sessions.tcp.getAll().forEach(tcpSession => allTcpSessions.push(tcpSession))
    // console.log(`Retransmissions: ${tcpRetransmission.resentBytesCount}b/${tcpRetransmission.allPacketsByteCount}b (${Math.floor(100 * (tcpRetransmission.resentBytesCount / tcpRetransmission.allPacketsByteCount))}%)`)
    console.log([
      '🌎 Overall information',
      '======================',
      `Total traffic: ${pretty(totals.bytesCount)}`,
      `TCP traffic: ${pretty(totals.tcpBytesCount)} (${percentage(totals.tcpBytesCount, totals.bytesCount)}% of all traffic)`,
      `UDP traffic: ${pretty(totals.udpBytesCount)} (${percentage(totals.udpBytesCount, totals.bytesCount)}% of all traffic)`
    ].join('\n'))
    console.log()

    console.log([
      '👯‍♀️ TCP Retransmission information',
      '=================================',
      'The TCP retransmission says something about how much TCP traffic is resent.',
      'It is not necesarrily a bad thing, but if the percentage is above 30% you could',
      'mention to the customer that there is a lot of TCP retransmissions and that they',
      'might want to look into that by using live monitor.',
      '',
      `Total TCP traffic: ${pretty(tcpRetransmission.allPacketsByteCount)} (${tcpRetransmission.allPacketsCount} packets)`,
      `Resent TCP traffic: ${pretty(tcpRetransmission.resentBytesCount)} (${tcpRetransmission.resentPacketsCount} packets)`,
      `TCP retransmisisons count for ${percentage(tcpRetransmission.resentBytesCount, tcpRetransmission.allPacketsByteCount)}% of all TCP traffic`
    ].join('\n'))
    console.log()

    const tlsTotal = allTcpSessions.filter(({ type }) => type === 'tls').reduce((tlsTotal, { bytes }) => tlsTotal + bytes, 0)
    const tlsMeta = allTcpSessions.filter(({ type }) => type === 'tls').reduce((tlsMeta, { tls: { metaTraffic } }) => tlsMeta + metaTraffic, 0)
    console.log([
      '🔒 TLS Information',
      '==================',
      'The TLS information is a good indicator on whether or not the customer might',
      'gain from using connectors. If the meta traffic is above 50%, it means that they',
      'could at least save 50% of that part of the traffic sent over the TLS.',
      '',
      `Total traffic sent over TLS: ${pretty(tlsTotal)} (${percentage(tlsTotal, totals.bytesCount)}% of all traffic)`,
      `Meta traffic sent over TLS: ${pretty(tlsMeta)} (${percentage(tlsMeta, totals.bytesCount)}% of all traffic [this could be removed if using connectors])`,
    ].join('\n'))
    console.log()

    console.log([
      '🚦 Hosts information',
      '====================',
      'The information about hosts is something that could be shared with the customer',
      'It can help them visualize if there are any hosts that shouldn\'t be there, or',
      'if any of them use too much traffic.',
      ''
    ]
      .concat(Object
        .entries(trafficToHosts)
        .map(([ip, { bytesUp, bytesDown }]) =>
          `${strLen(ip, 15)} ${strLen(pretty(bytesUp, { minimumFractionDigits: 2 }), 12, 'right')}⬆ ${strLen(pretty(bytesDown, { minimumFractionDigits: 2 }), 12, 'right')}⬇ (${percentage(bytesUp + bytesDown, totals.bytesCount)}% of all traffic)`
        ))
      .join('\n'))
  })

function percentage (part, all) {
  return Math.floor(100 * (part / all))
}

function strLen (str, length, align = 'left') {
  if (align === 'left') return str + Array(length - str.length).fill(' ').join('')
  if (align === 'right') return Array(length - str.length).fill(' ').join('') + str
}

const ipHeaderParser = new BinaryParser()
  .endianess('big')
  .bit4('version')
  .bit4('headerLength')
  .uint8('tos')
  .uint16('packetLength')
  .uint16('id')
  .bit3('offset')
  .bit13('fragOffset')
  .uint8('ttl')
  .uint8('protocol')
  .uint16('checksum')
  .array('src', {
    type: 'uint8',
    length: 4,
  })
  .array('dst', {
    type: 'uint8',
    length: 4,
  })

const tcpHeaderParser = new BinaryParser()
  .endianess('big')
  .uint16('srcPort')
  .uint16('dstPort')
  .uint32('seq')
  .uint32('ack')
  .bit4('dataOffset')
  .bit6('reserved')
  .nest('flags', {
    type: new BinaryParser()
      .bit1('urg')
      .bit1('ack')
      .bit1('psh')
      .bit1('rst')
      .bit1('syn')
      .bit1('fin'),
  })
  .uint16('windowSize')
  .uint16('checksum')
  .uint16('urgentPointer')

const udpHeaderParser = new BinaryParser()
  .endianess('big')
  .uint16('srcPort')
  .uint16('dstPort')
  .uint16('length')
  .uint16('checksum')

const tlsHeaderParser = new BinaryParser()
  .endianess('big')
  .uint8('type')
  .uint16('version')
  .uint16('length')

function ip (buf) {
  return `${buf[0]}.${buf[1]}.${buf[2]}.${buf[3]}`
}
