import { IParser } from './parsers'

export class IPv4Parser implements IParser<IPv4Packet> {
    parse(data: Uint8Array): IPv4Packet {
        const view = new DataView(data.buffer);

        const version = view.getUint8(0) >>> 4;
        const headerLength = view.getUint8(0) << 4 >>> 4;
        const dscp = view.getUint8(1) >>> 2;
        const ecn = view.getUint8(1) << 6 >>> 6;
        const totalLength = view.getUint16(2, false);
        const identification = view.getUint16(4, false);
        const flags = view.getUint8(6) >>> 5;
        const fragmentOffset = view.getUint16(6, false) << 2 >>> 2;
        const ttl = view.getUint8(8);
        const protocol = view.getUint8(9);
        const headerChecksum = view.getUint16(10, false);
        const srcAddress = data.slice(12, 16);
        const destAddress = data.slice(16, 20);

        const packetData = data.slice(headerLength * 4, data.length);

        return new IPv4Packet(version, headerLength, dscp, ecn, totalLength, identification, flags, fragmentOffset, ttl, protocol, headerChecksum, srcAddress, destAddress, packetData);
    }
}

export class IPv4Packet {
    readonly version : number;
    readonly headerLength : number;
    readonly dscp : number;
    readonly ecn : number;
    readonly totalLength : number;
    readonly identification : number;
    readonly flags : number;
    readonly fragmentOffset : number;
    readonly ttl : number;
    readonly protocol : number;
    readonly headerChecksum : number;
    readonly sourceAddress : Uint8Array;
    readonly destinationAddress : Uint8Array;
    readonly data : Uint8Array;

    constructor(version : number, headerLength : number, dscp : number, ecn : number, totalLength : number, identification : number, flags : number, fragmentOffset : number, ttl : number, protocol : number, headerChecksum : number, sourceAddress : Uint8Array, destinationAddress : Uint8Array, data : Uint8Array) {
        this.version = version;
        this.headerLength = headerLength;
        this.dscp = dscp;
        this.ecn = ecn;
        this.totalLength = totalLength;
        this.identification = identification;
        this.flags = flags;
        this.fragmentOffset = fragmentOffset;
        this.ttl = ttl;
        this.protocol = protocol;
        this.headerChecksum = headerChecksum;
        this.sourceAddress = sourceAddress;
        this.destinationAddress = destinationAddress;
        this.data = data;
    }
}