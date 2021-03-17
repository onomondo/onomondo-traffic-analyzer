const tcpSessions = {}
const udpSessions = {}

module.exports = {
  tcp: {
    set ({ ipHeader, tcpHeader: innerHeader, value }) {
      const key = getKey({ ipHeader, innerHeader })
      tcpSessions[key] = value
    },
    get ({ ipHeader, tcpHeader: innerHeader }) {
      const key = getKey({ ipHeader, innerHeader })
      return tcpSessions[key]
    },
    getAll () {
      return Object.values(tcpSessions)
    }
  },
  udp: {
    set ({ ipHeader, udpHeader: innerHeader, value }) {
      const key = getKey({ ipHeader, innerHeader })
      udpSessions[key] = value
    },
    get ({ ipHeader, udpHeader: innerHeader }) {
      const key = getKey({ ipHeader, innerHeader })
      return udpSessions[key]
    },
    getAll () {
      return udpSessions
    }
  }
}

function getKey ({ ipHeader, innerHeader }) {
  const hosts = [
    `${ip(ipHeader.src)}:${innerHeader.srcPort}`,
    `${ip(ipHeader.dst)}:${innerHeader.dstPort}`
  ]
  const sortedHosts = hosts.sort((h1, h2) => h1.localeCompare(h2))
  return sortedHosts.join('<->')
}

function ip (buf) {
  return `${buf[0]}.${buf[1]}.${buf[2]}.${buf[3]}`
}
