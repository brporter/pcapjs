import * as assert from "assert";
import { IPv4Packet, IPv4Parser } from './ip';

describe('IPv4 Parsing', () => {
    it("should parse a simple packet correctly", () => {
        const packet = new Uint8Array([
            0x84, 0x00, 0x18, 0x00, // Version, IHL, DSCP, ECN, Total Length
            0x00, 0x00, 0x00, 0x00, // identification, flags, fragment offset
            0x80, 0x01, 0x02, 0x03, // TTL, protocol, header checksum
            0x01, 0x02, 0x03, 0x04, // source address
            0x05, 0x06, 0x07, 0x08, // destination address
            0xDE, 0xAD, 0xBE, 0xEF  // data
        ]);
    
        const parser = new IPv4Parser();
        const result = parser.parse(packet);
    
        assert.strictEqual(result.version, 4, "parsed packet version was incorrect value");
    });
});