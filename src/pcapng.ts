
export enum BlockType {
    Unknown = 0xffffffff,
    SectionHeader = 0x0a0d0d0a,
    InterfaceDescription = 0x1,
    InterfaceStatistics = 0x5,
    EnhancedPacket = 0x6,
    SimplePacket = 0x3,
    NameResolution = 0x4,
    Custom = 0xBAD,
    CustomNoCopy = 0x40000BAD
}

export class Block {
    blockType : BlockType;
    blockTotalLength : number;
    blockBytes : Uint8Array;
    options : Record[];

    constructor(blockType: BlockType, blockTotalLength: number, blockBytes: Uint8Array, options: Record[])
    {
        this.blockType = blockType;
        this.blockTotalLength = blockTotalLength;
        this.blockBytes = blockBytes;
        this.options = options;
    }
}

export class SectionHeaderBlock extends Block {
    readonly littleEndian : boolean;
    readonly majorVersion: number;
    readonly minorVersion: number;
    readonly sectionLength: bigint;

    constructor(blockTotalLength : number, blockBytes : Uint8Array, majorVersion : number, minorVersion: number, sectionLength: bigint, options: Record[], littleEndian: boolean) {
        super(BlockType.SectionHeader, blockTotalLength, blockBytes, options);
        this.majorVersion = majorVersion;
        this.minorVersion = minorVersion;
        this.sectionLength = sectionLength;
        this.littleEndian = littleEndian;
    }
}

export class InterfaceDescriptionBlock extends Block {
    readonly linkType : number;
    readonly snapLength : number;

    constructor(blockTotalLength: number, blockBytes: Uint8Array, linkType: number, snapLength: number, options: Record[]) {
        super(BlockType.InterfaceDescription, blockTotalLength, blockBytes, options);
        this.linkType = linkType;
        this.snapLength = snapLength;
    }
}

export class InterfaceStatisticsBlock extends Block {
    readonly interfaceId : number;
    readonly timestampHigh : number;
    readonly timestampLow : number;

    constructor(blockTotalLength : number, blockBytes: Uint8Array, interfaceId : number, timestampHigh : number, timestampLow : number, options : Record[]) {
        super(BlockType.InterfaceStatistics, blockTotalLength, blockBytes, options);
        this.interfaceId = interfaceId;
        this.timestampHigh = timestampHigh;
        this.timestampLow = timestampLow;
    }
}

export class EnhancedPacketBlock extends Block {
    readonly interfaceId : number;
    readonly timestampHigh: number;
    readonly timestampLow: number;
    readonly capturedLength : number;
    readonly originalLength : number;

    constructor(blockTotalLength: number, blockBytes: Uint8Array, interfaceId : number, timestampHigh : number, timestampLow : number, capturedLength : number, originalLength : number, options : Record[]) {
        super(BlockType.EnhancedPacket, blockTotalLength, blockBytes, options);
        
        this.interfaceId = interfaceId;
        this.timestampHigh = timestampHigh;
        this.timestampLow = timestampLow;
        this.capturedLength = capturedLength;
        this.originalLength = originalLength;
    }
}

export class NameResolutionBlock extends Block {
    readonly records : Record[];

    constructor(blockTotalLength : number, blockBytes: Uint8Array, records : Record[], options : Record[]) {
        super(BlockType.NameResolution, blockTotalLength, blockBytes, options)
        this.records = records;
    }
}

export class Record {
    readonly code : number;
    readonly length : number;
    readonly value : Uint8Array;
    readonly paddedLength : number;
    readonly isLittleEndian : boolean;

    constructor(code: number, length: number, value: Uint8Array, isLittleEndian : boolean) {
        this.code = code;
        this.length = length;
        this.paddedLength = length % 4 == 0 ? length : length - (length % 4) + 4;
        this.value = value;
        this.isLittleEndian = isLittleEndian;
    }

    asBigUInt64() : bigint {
        return new DataView(this.value.buffer).getBigUint64(0, this.isLittleEndian);
    }

    asBigInt64() : bigint {
        return new DataView(this.value.buffer).getBigInt64(0, this.isLittleEndian);
    }

    asInt32() : number {
        return new DataView(this.value.buffer).getInt32(0, this.isLittleEndian);
    }

    asUint32() : number {
        return new DataView(this.value.buffer).getUint32(0, this.isLittleEndian);
    }

    asString() : string {
        return this.toString();
    }

    toString() : string {
        return String.fromCharCode.apply(String, Array.from(this.value.filter( (v) => { return v != 0; } )))
    }
}

export class Section {
    readonly block : SectionHeaderBlock;
    list : Block[];

    constructor(block : SectionHeaderBlock) {
        this.block = block;
        this.list = [];
    }
}

export class Capture {
    list : Section[];

    constructor() {
        this.list = [];
    }
}

export class Parser {
    constructor() {}

    async generateBlock(sectionLittleEndian : boolean, slice : Uint8Array) : Promise<Block> {
        return new Promise<Block>( async (resolve) => {
            const view = new DataView(slice.buffer);
            const blockType = <BlockType>this.getUint32(sectionLittleEndian, view, 0);
            
            let totalLength = this.getUint32(sectionLittleEndian, view, 4);

            if (blockType == BlockType.SectionHeader)
            {
                const magic = this.getUint32(sectionLittleEndian, view, 8);
                let sle = Parser.isSectionLittleEndian(magic);

                // re-parse total length in case our previously determined endianness is different for
                // this new section
                totalLength = this.getUint32(sle, view, 4);
                const majorVersion = this.getUint16(sle, view, 12);
                const minorVersion = this.getUint16(sle, view, 14);
                const sectionLength = this.getInt64(sle, view, 16);
                const options = await this.generateRecords(sle, slice.slice(24, totalLength - 4));

                // initial value of 4 - every block has an empty option block at least
                // v.paddedLength - padded size of the option value
                // + 4 - to account for the option code and length fields
                let optionsLength = options.reduce( (a, v) => a + v.paddedLength + 4, 4);

                resolve(new SectionHeaderBlock(
                    totalLength, 
                    slice.slice(24 + optionsLength, totalLength - 4), 
                    majorVersion, 
                    minorVersion, 
                    sectionLength, 
                    options,
                    sle));
            } else if (blockType == BlockType.InterfaceDescription) {
                const linkType = this.getUint16(sectionLittleEndian, view, 8);
                const snapLength = this.getUint32(sectionLittleEndian, view, 12);
                const options = await this.generateRecords(sectionLittleEndian, slice.slice(16, totalLength - 4));

                resolve(new InterfaceDescriptionBlock(
                    totalLength,
                    slice.slice(16, totalLength - 4),
                    linkType,
                    snapLength,
                    options
                ));
            } else if (blockType == BlockType.InterfaceStatistics) {
                const interfaceId = this.getUint32(sectionLittleEndian, view, 8);
                const timestampHigh = this.getUint32(sectionLittleEndian, view, 12);
                const timestampLow = this.getUint32(sectionLittleEndian, view, 16);
                const options = await this.generateRecords(sectionLittleEndian, slice.slice(20, totalLength - 4));

                resolve(new InterfaceStatisticsBlock(
                    totalLength,
                    slice.slice(20, totalLength - 4),
                    interfaceId,
                    timestampHigh,
                    timestampLow,
                    options
                ));
            } else if (blockType == BlockType.NameResolution) {
                const records = await this.generateRecords(sectionLittleEndian, slice.slice(8, totalLength - 4));

                const recordLength = records.reduce( (a, v) => a + v.paddedLength + 4, 4);
                const options = await this.generateRecords(sectionLittleEndian, slice.slice(8 + recordLength, totalLength - 4));

                resolve(new NameResolutionBlock(totalLength, slice.slice(8, totalLength - 4), records, options));
            } else if (blockType == BlockType.EnhancedPacket) {
                const interfaceId = this.getUint32(sectionLittleEndian, view, 8);
                const timestampHigh = this.getUint32(sectionLittleEndian, view, 12);
                const timestampLow = this.getUint32(sectionLittleEndian, view, 16);
                const capturedLength = this.getUint32(sectionLittleEndian, view, 20);
                const originalLength = this.getUint32(sectionLittleEndian, view, 24);

                const paddedLength = (capturedLength % 4 == 0) ? capturedLength : capturedLength - (capturedLength % 4) + 4;
                const bodyBytes = slice.slice(28, 28 + paddedLength);

                const options = await this.generateRecords(sectionLittleEndian, slice.slice(28 + paddedLength, totalLength - 4));

                resolve(new EnhancedPacketBlock(
                    totalLength,
                    bodyBytes,
                    interfaceId,
                    timestampHigh,
                    timestampLow,
                    capturedLength,
                    originalLength,
                    options
                ));
            } else {
                resolve(new Block(blockType, totalLength, slice.slice(8, totalLength - 4), []));
            }
        });
    }

    async generateRecords(sectionLittleEndian : boolean, slice : Uint8Array) : Promise<Record[]> {
        return new Promise<Record[]>( async (resolve) => {
            const returnValue : Record[] = new Array(0);
            const view  = new DataView(slice.buffer);
            let offset = 0;
            
            while (offset < slice.length)
            {
                const optionCode = this.getUint16(sectionLittleEndian, view, offset);
                offset += 2;

                const optionLength = this.getUint16(sectionLittleEndian, view, offset);
                offset += 2;

                const optionValue = slice.slice(offset, offset + optionLength);
                offset += optionLength % 4 == 0 ? optionLength : optionLength - (optionLength % 4) + 4;
    
                if (optionCode == 0)
                {
                    break;
                }
    
                returnValue.push(
                    new Record(optionCode, optionLength, optionValue, sectionLittleEndian)
                )
            }

            resolve(returnValue);
        });
    }

    async parse(buffer : Uint8Array) : Promise<Capture> {
        return new Promise<Capture>( async (resolve) => {
            let capture : Capture = new Capture();
            let currentSection : Section | null = null;

            let offset = 0;
            let parseCount = 0;
            let isLittleEndian = false;

            while (offset < buffer.length) {
                if (currentSection != null) {
                    isLittleEndian = (<Section>currentSection).block.littleEndian;
                }

                let block = await this.generateBlock(isLittleEndian, buffer.slice(offset, buffer.length))

                if (block.blockType == BlockType.SectionHeader) {
                    let shb = <SectionHeaderBlock>block;
                    currentSection = new Section(shb);
                    capture.list.push(currentSection);
                } else {
                    currentSection?.list.push(block);
                }

                offset += block.blockTotalLength;
                parseCount++;
            }

            resolve(capture);
        });
    }

    getInt64(littleEndian : boolean, view : DataView, offset : number) : bigint
    {
        return view.getBigInt64(offset, littleEndian);
    }

    getUint32(littleEndian : boolean, view : DataView, offset : number) : number
    {
        return littleEndian ? view.getUint32(offset) : Parser.swapOrder32(view.getUint32(offset));
    }

    getUint16(littleEndian : boolean, view : DataView, offset : number) : number
    {
        return littleEndian ? view.getUint16(offset) : Parser.swapOrder16(view.getUint16(offset));
    }

    static isSystemLittleEndian() : boolean {
        let ab = new ArrayBuffer(2);
        let u8 = new Uint8Array(ab);
        let u16 = new Uint16Array(ab);

        u8[0] = 0xAA;
        u8[1] = 0xBB;

        return u16[0] == 0xBBAA;
    }

    static isSectionLittleEndian(magic : number) : boolean {
        return magic == 0x4D3C2B1A;
    }

    static swapOrder16(val: number) : number
    {
        let result : number = 0;

        result |= ((val & 0x00FF) << 8);
        result |= ((val & 0xFF00) >>> 8);

        return result >>> 0;
    }

    static swapOrder32(val: number) : number
    {
        let result : number = 0;

        result |= ((val & 0x000000FF) << 24);
        result |= ((val & 0x0000FF00) << 8);
        result |= ((val & 0x00FF0000) >> 8);
        result |= ((val & 0xFF000000) >>> 24);

        return result >>> 0;
    }

    static getBytes(val: number) : Uint8Array
    {
        const buf = new ArrayBuffer(4);
        const u32 = new Uint32Array(buf);
        const u8 = new Uint8Array(buf);

        u32[0] = val;

        return u8;
    }

    static blockTypeToName(val: BlockType) : String {
        switch (val) {
            case BlockType.SectionHeader:
                return "Section Header";
            case BlockType.SimplePacket:
                return "Simple Packet";
            case BlockType.NameResolution:
                return "Name Resolution";
            case BlockType.InterfaceStatistics:
                return "Interface Statistics";
            case BlockType.InterfaceDescription:
                return "Interface Description";
            case BlockType.EnhancedPacket:
                return "Enhanced Packet";
            case BlockType.CustomNoCopy:
                return "Custom (Do Not Copy)";
            case BlockType.Custom:
                return "Custom";
        }

        return "Unknown";
    }

    private static map = new Map<BlockType, Map<number, String>>([
        [BlockType.SectionHeader, new Map<number, String>([
            [2, "Hardware"],
            [3, "Operating System"],
            [4, "Application"]
        ])],
        [BlockType.InterfaceDescription, new Map<number, String>([
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
        [BlockType.EnhancedPacket, new Map<number, String>([
            [2, "Flags"],
            [3, "Hash"],
            [4, "Drop Count"]
        ])],
        [BlockType.InterfaceStatistics, new Map<number, String>([
            [2, "Start Time"],
            [3, "End Time"],
            [4, "Receive Count"],
            [5, "Drop Count"],
            [6, "Accepted by Filter Count"],
            [7, "OS Drop Count"],
            [8, "Delivered to User"]
        ])]
    ]);

    static optionCodeToName(code : number, blockType: BlockType) : String {
        if (code == 1) {
            return "Comment";
        }

        return Parser.map.get(blockType)?.get(code) ?? "Unknown Block Type / Code Combination";
    }
}