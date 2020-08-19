import * as assert from "assert";
import * as fs from "fs";
import * as packet from "./pcapng"
import * as analyzers from "./protocols/ethernet"

describe("Parser Utility Methods", () => {
    it("should reverse the bytes of whatever 32-bit number is passed in", () => {
        let result = packet.Parser.swapOrder32(0xAABBCCDD);
        assert.strictEqual(result, 0xDDCCBBAA, "bytes were not swapped properly.");
    });

    it("should reverse the bytes of whatever 32-bit number is passed in, even if they contain trailing bytes that are zero", () => {
        let result = packet.Parser.swapOrder32(0xFFBBCC00);
        assert.strictEqual(result, 0x00CCBBFF, "bytes were not swapped properly.");
    });

    it("should reverse the bytes of whatever 32-bit number is passed in, even if they contain leading bytes that are zero", () => {
        let result = packet.Parser.swapOrder32(0x00FFBBCC);
        assert.strictEqual(result, 0xCCBBFF00, "bytes were not swapped properly.");
    });

    it("should reverse the bytes of whatever 16-bit number is passed in", () => {
        let result = packet.Parser.swapOrder16(0xAABB);
        assert.strictEqual(result, 0xBBAA, "bytes were not swapped properly.");
    });

    it("should reverse the bytes of whatever 16-bit number is passed in, even if they contain trailing bytes that are zero", () => {
        let result = packet.Parser.swapOrder16(0xAA00);
        assert.strictEqual(result, 0x00AA, "bytes were not swapped properly.");
    });

    it("should reverse the bytes of whatever 16-bit number is passed in, even if they contain leading bytes that are zero", () => {
        let result = packet.Parser.swapOrder16(0x00BB);
        assert.strictEqual(result, 0xBB00, "bytes were not swapped properly.");
    });
});

describe("Block Type Parsing", () => {
    it("all block types should convert to a string representation", () => {
        assert.strictEqual(packet.Parser.blockTypeToName(packet.BlockType.Custom), "Custom");
        assert.strictEqual(packet.Parser.blockTypeToName(packet.BlockType.CustomNoCopy), "Custom (Do Not Copy)");
        assert.strictEqual(packet.Parser.blockTypeToName(packet.BlockType.EnhancedPacket), "Enhanced Packet");
        assert.strictEqual(packet.Parser.blockTypeToName(packet.BlockType.InterfaceDescription), "Interface Description");
        assert.strictEqual(packet.Parser.blockTypeToName(packet.BlockType.InterfaceStatistics), "Interface Statistics");
        assert.strictEqual(packet.Parser.blockTypeToName(packet.BlockType.NameResolution), "Name Resolution");
        assert.strictEqual(packet.Parser.blockTypeToName(packet.BlockType.SimplePacket), "Simple Packet");
        assert.strictEqual(packet.Parser.blockTypeToName(packet.BlockType.SectionHeader), "Section Header");
        assert.strictEqual(packet.Parser.blockTypeToName(packet.BlockType.Unknown), "Unknown");
    });
});

describe("Record Type Conversions and Parsing", () => {
    it("should produce a string properly", () => {
        const data = new Uint8Array([
            102, 111, 111, 0x00
        ]);

        const r = new packet.Record(1, 3, data, false);

        assert.strictEqual(r.asString(), "foo", "record produced incorrect string value");
    });

    it("should produce a signed number properly", () => {
        const data = new Uint8Array([
            0xFF, 0xFF, 0xFF, 0xFF
        ]);

        const r = new packet.Record(1, 3, data, false);

        assert.strictEqual(r.asInt32(), -1, "record produced incorrect signed integer value");
    });

    it("should produce an unsigned number properly", () => {
        const data = new Uint8Array([
            0xFF, 0xFF, 0xFF, 0xFF
        ]);

        const r = new packet.Record(1, 3, data, false);

        assert.strictEqual(r.asUint32(), 4294967295, "record produced incorrect signed integer value");
    });

    it("should produce an unsigned bigint properly", () => {
        const data = new Uint8Array([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ]);

        const r = new packet.Record(1, 3, data, false);

        const expected = BigInt(-1);

        assert.strictEqual(r.asBigInt64(), expected, "record produced incorrect signed bigint value");
    });

    it("should produce an unsigned bigint properly", () => {
        const data = new Uint8Array([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        const r = new packet.Record(1, 3, data, false);
        const expected = BigInt(72057594037927936);

        assert.strictEqual(r.asBigUInt64(), expected, "record produced incorrect unsigned bigint value");
    });
})

describe("Packet Parsing", () => {

    it("should convert a number to a byte array", () => {
        const result = packet.Parser.getBytes(1);

        assert.strictEqual(result.length, 4, "returned value had incorrect length");
        assert.strictEqual(result.every( (v, i) => {
            return v == [0x01, 0x00, 0x00, 0x00][i]
        }), true, "return byte array had incorrect bytes");
    });

    it("should generate a section header block correctly", async () => {
        const data = new Uint8Array(
            [
                0x0A, 0x0D, 0x0D, 0x0A, // Block Type
                0x20, 0x00, 0x00, 0x00, // Total Length
                0x4D, 0x3C, 0x2B, 0x1A, // Magic Number
                0x01, 0x00,             // Major Version (1)
                0x17, 0x00,             // Minor Version (17)
                0x00, 0x00, 0x00, 0x00, // Section Length
                0x00, 0x00, 0x00, 0x00, // --
                0x00, 0x00,             // Option Code
                0x00, 0x00,             // Option Length
                0x20, 0x00, 0x00, 0x00  // Total Length
            ]);

        // section header block, big-endian
        const p = new packet.Parser();
        let block = <packet.SectionHeaderBlock>(await p.generateBlock(false, data));

        assert.strictEqual(block.blockType, packet.BlockType.SectionHeader, "generated block was of the incorrect type");
        assert.strictEqual(block.blockBytes.length, 0, "generated block had an incorrect body length");
        assert.strictEqual(block.options.length, 0, "generate block had an incorrect number of options");
        assert.strictEqual(block.majorVersion, 1, "generated block had incorrect major version");
        assert.strictEqual(block.minorVersion, 23, "generated block had incorrect minor version");
        assert.strictEqual(block.blockTotalLength, 32, "generated block had an incorrect total length");
    });

    it("should generate a section header block that has a block body correctly", async () => {
        const data = new Uint8Array(
            [
                0x0A, 0x0D, 0x0D, 0x0A, // Block Type
                0x24, 0x00, 0x00, 0x00, // Total Length
                0x4D, 0x3C, 0x2B, 0x1A, // Magic Number
                0x02, 0x00,             // Major Version
                0x02, 0x00,             // Minor Version
                0x00, 0x00, 0x00, 0x00, // Section Length
                0x00, 0x00, 0x00, 0x00, // --
                0x00, 0x00,             // Option Code
                0x00, 0x00,             // Option Length
                0xDE, 0xAD, 0xBE, 0xEF, // Body Bytes
                0x24, 0x00, 0x00, 0x00  // Total Length
            ]);

        // section header block, big-endian
        const p = new packet.Parser();
        let block = <packet.SectionHeaderBlock>(await p.generateBlock(false, data));

        assert.strictEqual(block.blockType, packet.BlockType.SectionHeader, "generated block was of the incorrect type");
        assert.strictEqual(block.blockBytes.length, 4, "generated block had an incorrect body length");

        assert.strictEqual(
            block.blockBytes.every( 
                (value, index, array) => { 
                    let required = [0xDE, 0xAD, 0xBE, 0xEF];  

                    return index < required.length && array[index] == required[index];
                }), true, "generated block had an incorrect body bytes");

        assert.strictEqual(block.options.length, 0, "generate block had an incorrect number of options");
        assert.strictEqual(block.majorVersion, 2, "generated block had incorrect major version");
        assert.strictEqual(block.minorVersion, 2, "generated block had incorrect minor version");

        assert.strictEqual(block.blockTotalLength, 36, "generated block had an incorrect total length");
    });

    it("should generate a section header block that has options and a block body correctly", async () => {
        const data = new Uint8Array(
            [
                0x0A, 0x0D, 0x0D, 0x0A, // Block Type
                0x34, 0x00, 0x00, 0x00, // Total Length
                0x4D, 0x3C, 0x2B, 0x1A, // Magic Number
                0x02, 0x00,             // Major Version
                0x02, 0x00,             // Minor Version
                0x00, 0x00, 0x00, 0x00, // Section Length
                0x00, 0x00, 0x00, 0x00, // --
                0x01, 0x00,             // Option Code
                0x03, 0x00,             // Option Length
                102, 111, 111, 0x00,    // foo
                0x01, 0x00,             // Option Code
                0x03, 0x00,             // Option Length
                102, 111, 111, 0x00,    // foo
                0x00, 0x00,             // Option Code
                0x00, 0x00,             // Option Length
                0xDE, 0xAD, 0xBE, 0xEF, // Body Bytes
                0x34, 0x00, 0x00, 0x00  // Total Length
            ]);

        // section header block, big-endian
        const p = new packet.Parser();
        let block = <packet.SectionHeaderBlock>(await p.generateBlock(false, data));

        assert.strictEqual(block.blockType, packet.BlockType.SectionHeader, "generated block was of the incorrect type");
        assert.strictEqual(block.blockBytes.length, 4, "generated block had an incorrect body length");

        assert.strictEqual(
            block.blockBytes.every( 
                (value, index, array) => { 
                    let required = [0xDE, 0xAD, 0xBE, 0xEF];  

                    return index < required.length && array[index] == required[index];
                }), true, "generated block had incorrect body bytes");

        assert.strictEqual(block.options.length, 2, "generate block had an incorrect number of options");
        assert.strictEqual(block.options[0].toString(), "foo", "generated block had unexpected option value");
        assert.strictEqual(block.options[1].toString(), "foo", "generated block had unexpected option value");
        assert.strictEqual(block.majorVersion, 2, "generated block had incorrect major version");
        assert.strictEqual(block.minorVersion, 2, "generated block had incorrect minor version");

        assert.strictEqual(block.blockTotalLength, 52, "generated block had an incorrect total length");
    });

    it("should generate an interface description block correctly", async () => {
        const data = new Uint8Array(
            [
                0x01, 0x00, 0x00, 0x00, // Interface Description Block
                0x20, 0x00, 0x00, 0x00, // Block Total Length
                0x01, 0x00,             // Link Type
                0x00, 0x00,             // Reserved
                0x64, 0x00, 0x00, 0x00, // Snap Length
                0x01, 0x00,             // Option Code
                0x03, 0x00,             // Option Length
                102, 111, 111, 0x00,    // foo
                0x00, 0x00,             // Option Code
                0x00, 0x00,             // Option Length
                0x20, 0x00, 0x00, 0x00  // Block Total Length
            ]);
        
        const p = new packet.Parser();
        
        let block = <packet.InterfaceDescriptionBlock>(await p.generateBlock(false, data));

        assert.strictEqual(block.blockTotalLength, 32, "generated block had an incorrect total length");
        assert.strictEqual(block.options.length, 1, "generated block had an incorrect number of options");
        assert.strictEqual(block.linkType, 1, "generated block had an incorrect link type");
        assert.strictEqual(block.snapLength, 100, "generated block had an incorrect snap length");
    });

    it("should generate an enhanced packet block correctly", async() => {
        const data = new Uint8Array(
            [
                0x06, 0x00, 0x00, 0x00, // Block Type
                0x8c, 0x00, 0x00, 0x00, // Block Total Length
                0x01, 0x00, 0x00, 0x00, // Interface ID
                0x01, 0x02, 0x03, 0x04, // Timestamp (High)
                0x04, 0x05, 0x06, 0x07, // Timestamp (Low)
                0x64, 0x00, 0x00, 0x00, // Captured Packet Length
                0x00, 0x5a, 0x00, 0x00, // Original Packet Length,
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                0x00, 0x00,             // Option Code
                0x00, 0x00,             // Option Length
                0x8c, 0x00, 0x00, 0x00  // Block Total Length
            ]);

        const p = new packet.Parser();
        const block = <packet.EnhancedPacketBlock>(await p.generateBlock(false, data));

        assert.strictEqual(block.blockTotalLength, 140, "generated block had an incorrect total length");
        assert.strictEqual(block.options.length, 0, "generated block contained no options");
        assert.strictEqual(block.blockBytes.length, 100, "generated block had an incorrect number of body bytes");
        assert.strictEqual(
            block.blockBytes.every( 
                (value, index, array) => { 
                    let required = [0xDE, 0xAD, 0xBE, 0xEF];  

                    return array[index] == required[index % 4];
                }), true, "generated block had incorrect body bytes");
    });

    it("should generate an empty list of options from an empty option block correctly", async() => {
        const data = new Uint8Array(
            [
                0x00, 0x00, // option code
                0x00, 0x00, // option length
                // no option value
            ]);

        const p = new packet.Parser();

        let options = await p.generateRecords(false, data);

        assert.strictEqual(options.length, 0, "resultant options array was larger than expected");
    });

    it("should generate a comment option from an option block correctly", async() => {
        const data = new Uint8Array(
            [
                0x01, 0x00, // option code
                0x03, 0x00, // option length
                102, 111, 111, 0x00, // "foo"
                0x00, 0x00, // end of option
                0x00, 0x00, // end of option length
            ]);

        const p = new packet.Parser();

        let options = await p.generateRecords(false, data);

        assert.strictEqual(options.length, 1, "resultant options array was larger than expected");
        assert.strictEqual(options[0].toString(), "foo", "resultant option array did not contain the correct value.");
    });

    it("should generate multiple comment options from an option block correctly", async() => {
        const data = new Uint8Array(
            [
                0x01, 0x00, // option code
                0x03, 0x00, // option length
                102, 111, 111, 0x00, // "foo"
                0x01, 0x00, // option code
                0x03, 0x00, // option length
                102, 111, 111, 0x00, // "foo"
                0x00, 0x00, // end of option
                0x00, 0x00, // end of option length
            ]);

        const p = new packet.Parser();

        let options = await p.generateRecords(false, data);

        assert.strictEqual(options.length, 2, "resultant options array was larger than expected");
        assert.strictEqual(options[0].toString(), "foo", "resultant option array did not contain the correct value.");
        assert.strictEqual(options[1].toString(), "foo", "resultant option array did not contain the correct value.");
    });

    it("should parse a name resolution block correctly", async() => {
        const data = new Uint8Array([
            0x04, 0x00, 0x00, 0x00, // Block Type
            0x14, 0x00, 0x00, 0x00, // Total Length
            0x01, 0x00,             // Record Type
            0x04, 0x00,             // Record Value Length
            0x01, 0x02, 0x03, 0x04, // Record Value
            0x14, 0x00, 0x00, 0x00, // Total Length
        ]);

        const p = new packet.Parser();
        let block = <packet.NameResolutionBlock>(await p.generateBlock(false, data));

        assert.strictEqual(block.blockTotalLength, 20, "generated block had incorrect total length");
        assert.strictEqual(block.records.length, 1, "generated block had incorrect number of records");
        assert.strictEqual(
            block.records[0].value.every( (v, i, a) => { 
                let expected = [0x01, 0x02, 0x03, 0x04];
                return a[i] == expected[i];
            }), true, "generated block did not contain expected records");
    });

    it("should parse a name resolution block with options correctly", async() => {
        const data = new Uint8Array([
            0x04, 0x00, 0x00, 0x00, // Block Type
            0x2c, 0x00, 0x00, 0x00, // Total Length
            0x01, 0x00,             // Record Type
            0x04, 0x00,             // Record Value Length
            0x01, 0x02, 0x03, 0x04, // Record Value
            0x00, 0x00,             // End Record Block
            0x00, 0x00,
            0x01, 0x00,             // option code
            0x03, 0x00,             // option length
            102, 111, 111, 0x00,    // "foo"
            0x01, 0x00,             // option code
            0x03, 0x00,             // option length
            102, 111, 111, 0x00,    // "foo"
            0x00, 0x00,             // End Option Block
            0x00, 0x00,
            0x2c, 0x00, 0x00, 0x00, // Total Length
        ]);

        const p = new packet.Parser();
        let block = <packet.NameResolutionBlock>(await p.generateBlock(false, data));

        assert.strictEqual(block.blockTotalLength, 44, "generated block had incorrect total length");
        assert.strictEqual(block.records.length, 1, "generated block had incorrect number of records");
        assert.strictEqual(
            block.records[0].value.every( (v, i, a) => { 
                let expected = [0x01, 0x02, 0x03, 0x04];
                return a[i] == expected[i];
            }), true, "generated block did not contain expected records");
        assert.strictEqual(block.options.length, 2, "generated block had incorrect number of options");
        assert.strictEqual(
            block.options.every( (v, i, a) => { return v.toString() == "foo" }),
            true,
            "generated option block had incorrect values"
        );
    });

    it("should parse an interface statistics block correctly", async() => {
        const data = new Uint8Array([
            0x05, 0x00, 0x00, 0x00, // Block Type
            0x2c, 0x00, 0x00, 0x00, // Block Total Length
            0x01, 0x00, 0x00, 0x00, // Interface ID
            0x00, 0x00, 0x00, 0x00, // Timestamp High
            0x00, 0x00, 0x00, 0x00, // Timestamp Low
            0x01, 0x00,             // option code
            0x03, 0x00,             // option length
            102, 111, 111, 0x00,    // "foo"
            0x01, 0x00,             // option code
            0x03, 0x00,             // option length
            102, 111, 111, 0x00,    // "foo"
            0x00, 0x00,             // End Option Block
            0x00, 0x00,
            0x2c, 0x00, 0x00, 0x00  // Block Total Length
        ]);

        const p = new packet.Parser();
        
        const block = <packet.InterfaceStatisticsBlock>(await p.generateBlock(false, data));

        assert.strictEqual(block.blockType, packet.BlockType.InterfaceStatistics, "generated block was of the incorrect type" );
        assert.strictEqual(block.options.length, 2, "generated block had an incorrect number of options");
        assert.strictEqual(block.interfaceId, 1, "generated block had an incorrect interface id");
        assert.strictEqual(block.timestampHigh, 0, "generated block had an incorrect timestamp (high)");
        assert.strictEqual(block.timestampLow, 0, "generated block had an incorrect timestamp (low)");
        assert.strictEqual(
            block.options.every((v, i, a) => {
                return v.toString() == "foo"
            }), true, "geneated block options had incorrect values");
    })

    it("should parse an unknown block correctly", async() => {
        const data = new Uint8Array([
            0xFF, 0xFF, 0xFF, 0xFF, // Block Type
            0x10, 0x00, 0x00, 0x00, // Block Total Length
            0x01, 0x02, 0x03, 0x04, // Interface ID
            0x10, 0x00, 0x00, 0x00  // Block Total Length
        ]);

        const p = new packet.Parser();
        
        const block = await p.generateBlock(false, data);

        assert.strictEqual(block.blockType, packet.BlockType.Unknown, "generated block was of the incorrect type" );
        assert.strictEqual(block.options.length, 0, "generated block had an incorrect number of options");
        assert.strictEqual(block.blockBytes.length, 4, "generated block had an incorrect number of body bytes");
        assert.strictEqual(block.blockBytes.every( (v, i) => {
            return v == [0x01, 0x02, 0x03, 0x04][i];
        }), true, "generated block had incorrect body bytes");

        assert.strictEqual(
            block.options.every((v, i, a) => {
                return v.toString() == "foo"
            }), true, "generated block options had incorrect values");
    })

    it ("should detect system endianness correctly", () => {
        const ab = new ArrayBuffer(2);
        const u8 = new Uint8Array(ab);
        const u16 = new Uint16Array(ab);
        u16[0] = 0xAABB;

        assert.strictEqual(u8[0] == 0xBB && u8[1] == 0xAA, packet.Parser.isSystemLittleEndian(), "detected endianness did not match system endianness");
    });

    it ("should convert block type and option codes to descriptive option names", () =>{
        const map = new Map<packet.BlockType, Map<number, String>>([
            [packet.BlockType.SectionHeader, new Map<number, String>([
                [1, "Comment"],
                [2, "Hardware"],
                [3, "Operating System"],
                [4, "Application"],
                [5, "Unknown Block Type / Code Combination"]
            ])],
            [packet.BlockType.InterfaceDescription, new Map<number, String>([
                [1, "Comment"],
                [2, "Interface Name"],
                [3, "Desccriptoin"],
                [4, "IP Address (IPv4)"],
                [5, "IP Address (IPv6)"],
                [6, "MAC Address"],
                [7, "EUI Address"],
                [8, "Interface Speed"],
                [9, "Interface Timestamp Resolution"],
                [10, "Time Zone"],
                [11, "Filter"],
                [12, "Operating System"],
                [13, "FCS Length"],
                [14, "Timestamp Offset"]
            ])],
            [packet.BlockType.EnhancedPacket, new Map<number, String>([
                [2, "Flags"],
                [3, "Hash"],
                [4, "Drop Count"]
            ])],
            [packet.BlockType.InterfaceStatistics, new Map<number, String>([
                [2, "Start Time"],
                [3, "End Time"],
                [4, "Receive Count"],
                [5, "Drop Count"],
                [6, "Accepted by Filter Count"],
                [7, "OS Drop Count"],
                [8, "Delivered to User"]
            ])]
        ]);

        map.forEach( (v, blockType) => {
            v.forEach( (name, code) => {
                assert.strictEqual(packet.Parser.optionCodeToName(code, blockType), name, `conversion of ${packet.Parser.blockTypeToName(blockType)} with option code ${code} to name resulted in an incorrect value.`)
            })
        })
    });

    it("should parse and generate a capture data structure correctly", async() => {
        const dataBytes = fs.readFileSync("examples/file.pcapng");
        const data = new Uint8Array(dataBytes);

        const p = new packet.Parser();
        
        let capture = await p.parse(data);

        assert.strictEqual(capture.list.length, 1, "parsed capture had an incorrect number of sections");

        capture.list.forEach( e => {
            console.log(`Section has ${e.list.length} blocks.`);
            e.block.options.forEach( e => {
                console.log(`  Section Header Block has option '${packet.Parser.optionCodeToName(e.code, packet.BlockType.SectionHeader)} (${e.code})' with value '${e.toString()}'`);
            })

            e.list.forEach( e => {
                console.log(`Block is of type ${packet.Parser.blockTypeToName(e.blockType)}`)
                let blockType = e.blockType;

                e.options.forEach( e => {
                    console.log(`  Block has option '${packet.Parser.optionCodeToName(e.code, blockType)} (${e.code})' with value '${e.toString()}'`);
                })

                if (blockType == packet.BlockType.EnhancedPacket) {
                    const p = new analyzers.EthernetParser();
                    const result = p.parse(e.blockBytes);
                    
                    const destString = result.destination.reduce( (a, v) => a += "-" + v.toString(16), "").substr(1, 17);
                    const srcString = result.source.reduce( (a, v) => a += "-" + v.toString(16), "").substr(1, 17);

                    console.log(`    Block has destination of '${destString}' and source of '${srcString}'`);
                    const ip = result.next();

                    console.log(`        Packet has destination of '${ip.destinationAddress}' and source of '${ip.sourceAddress}'`);
                }
            });
        });
    });
});