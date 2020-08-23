import * as assert from "assert";
import { BitProcessor } from './bitprocessor'

describe('Bit Descriptor Processing Tests', () => {
    it('should parse an IPv4 byte array properly', () => {
        const bp = new BitProcessor();
        const data = new Uint8Array([
            0x45, 0xF3, 0x18, 0x00, // Version, IHL, DSCP, ECN, Total Length
            0x00, 0x00, 0x2E, 0xFF, // identification, flags, fragment offset
            0x80, 0x01, 0x02, 0x03, // TTL, protocol, header checksum
            0x01, 0x02, 0x03, 0x04, // source address
            0x05, 0x06, 0x07, 0x08, // destination address
            0xDE, 0xAD, 0xBE, 0xEF  // data
        ]);

        // const definition = `{
        //     "fields": [
        //         { "name": "version", "length": 4 },
        //         { "name": "ihl", "length": 4, "type": "length", "factor": 4},
        //         { "name": "tos", "length": 8 },
        //         { "name": "totalLength", "length": 16, "type": "length", "factor": 1 },
        //         { "name": "identification", "length": 16 },
        //         { "name": "flags", "length": 3 },
        //         { "name": "fragmentOffset", "length": 13 },
        //         { "name": "ttl", "length": 16 },
        //         { "name": "protocol", "length": 16 },
        //         { "name": "headerChecksum", "length": 32 },
        //         { "name": "sourceAddress", "length": 64 },
        //         { "name": "destinationAddress", "length": 64 },
        //         { "name": "options", "lengthExpression": "this.ihl > 5 ? (this.ihl * 4 - 20) : 0" },
        //         { "name": "payload", "lengthExpression": "this.totalLength - (this.ihl * 4)" }
        //     ]
        // }`;
        const definition = `{
                "fields": [
                    { "name": "version", "length": 4 },
                    { "name": "ihl", "length": 4, "type": "length", "factor": 4},
                    { "name": "tos", "length": 8 },
                    { "name": "totalLength", "length": 16, "type": "length", "factor": 1 },
                    { "name": "identification", "length": 16 },
                    { "name": "flags", "length": 3 },
                    { "name": "fragmentOffset", "length": 13 }
                ]
            }`;

        const p = bp.parse(definition, data);
        
        // assert.deepStrictEqual(p["payload"], new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]), "parsed packet did contain the expected payload");
    });

    it ('single-byte shifts work properly', () => {
        let len = 6;
        let data = new Uint8Array([0x68]); // 0110 0000
        let view = new DataView(data.buffer);
        let field = view.getUint8(0);

        let result = ((field << 8 - len) & 0xFF) >>> (8 - len)

        assert.strictEqual(result, 0x28, "result was unexpected");
    })

    it ('multi-byte shifts work properly', () => {
        let len = 13;
        let data = new Uint8Array([0xFF, 0xFF]); // 1111 1111 1111 1111
        let view = new DataView(data.buffer);
        let field = view.getUint16(0, true);

        let shiftTarget = 8 - (len % 8);
        let result = ((field << shiftTarget) & 0xFFFF) >>> shiftTarget

        assert.strictEqual(result, 0x1FFF, "result was unexpected");
    })

    // it ('multi-byte shifts work properly with a non-zero offset', () => {
    //     let offset = 13;
    //     let len = 3;
    //     let data = new Uint8Array([0xFF, 0xFF]); // 1111 1111 1111 1111
    //     let view = new DataView(data.buffer);
    //     let field = view.getUint16(0, true);

    //     let shiftTarget = offset;
    //     let result = ((field << shiftTarget) & 0xFFFF) >>> shiftTarget

    //     assert.strictEqual(result, 0x1FFF, "result was unexpected");
    // })

    it('field retrieval based on bit-length works', () => {
        const data = new Uint8Array([
            0xFF, 0xFF, 0xFF, 0xFF
        ]);

        const [oneByteValue, oneByteLength]  = BitProcessor.getField(data, 5);
        const [twoBytesValue, twoByteLength] = BitProcessor.getField(data, 13);
        const [threeBytesValue, threeByteLength] = BitProcessor.getField(data, 19);
        const [fourBytesValue, fourByteLength] = BitProcessor.getField(data, 27);
        
        assert.strictEqual(oneByteValue, 0xFF);
        assert.strictEqual(twoBytesValue, 0xFFFF);
        assert.strictEqual(threeBytesValue, 0xFFFFFFFF);
        assert.strictEqual(fourBytesValue, 0xFFFFFFFF);
        assert.strictEqual(oneByteLength, 1);
        assert.strictEqual(twoByteLength, 2);
        assert.strictEqual(threeByteLength, 4);
        assert.strictEqual(fourByteLength, 4);
    });

    it('should calcualte a mask properly', () => {
        const result = BitProcessor.calculateMask(0, 13);

        assert.strictEqual(result, 8191)
    });
});