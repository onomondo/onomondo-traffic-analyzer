const BinaryParser = require('binary-parser').Parser

module.exports = {
  ipHeaderParser: new BinaryParser()
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
    .buffer('data', {
      length: function () {
        return this.packetLength - (4 * this.headerLength)
      }
    }),
  tcpHeaderParser: new BinaryParser()
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
    .skip(function () {
      return (4 * this.dataOffset) - 20
    })
    .buffer('data', {
      readUntil: 'eof'
    }),
  udpHeaderParser: new BinaryParser()
    .endianess('big')
    .uint16('srcPort')
    .uint16('dstPort')
    .uint16('length')
    .uint16('checksum'),
  tlsHeaderParser: new BinaryParser()
    .endianess('big')
    .array('layers', {
      readUntil: 'eof',
      type: new BinaryParser()
        .uint8('type')
        .uint16('version')
        .uint16('length')
        .buffer('data', {
          length: function () {
            return this.length
          }
        })
    })
}
