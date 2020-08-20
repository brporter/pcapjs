import * as assert from "assert";
import { IPv4Packet, IPv4Parser } from './ip';

describe('IPv4 Parsing', () => {
    it("should parse a simple packet correctly", () => {
        const packet = new Uint8Array([
            0x45, 0xF3, 0x18, 0x00, // Version, IHL, DSCP, ECN, Total Length
            0x00, 0x00, 0x2E, 0xFF, // identification, flags, fragment offset
            0x80, 0x01, 0x02, 0x03, // TTL, protocol, header checksum
            0x01, 0x02, 0x03, 0x04, // source address
            0x05, 0x06, 0x07, 0x08, // destination address
            0xDE, 0xAD, 0xBE, 0xEF  // data
        ]);
    
        const parser = new IPv4Parser();
        const result = parser.parse(packet);
    
        assert.strictEqual(result.version, 4, "parsed packet version was incorrect value");
        assert.strictEqual(result.ecn, 3, "parsed packet contains incorrect ECN value");
        assert.strictEqual(result.flags, 1, "parsed flags were incorrect");
        assert.strictEqual(result.fragmentOffset, 0x0EFF, "parsed fragment offset was incorrect");
        assert.deepStrictEqual(result.sourceAddress, new Uint8Array([0x01, 0x02, 0x03, 0x04]), "parsed packet had incorrect source address");
        assert.deepStrictEqual(result.destinationAddress, new Uint8Array([0x05, 0x06, 0x07, 0x08]), "parsed packet had incorrect destination address");
        assert.deepStrictEqual(result.data, new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]), "parsed packet contained incorrect data");
    });
});