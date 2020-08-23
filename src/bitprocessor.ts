/* All networking protocols are just bit patterns that encode data and lengths in various ways. */

export class BitProcessor {
    parse(definition: string, data: Uint8Array) {
        const def = JSON.parse(definition);
        const view = new DataView(data.buffer);
        const returnValue = {};

        let offset = 0;

        for (let i = 0; i < def.fields.length; i++)
        {
            let fieldDef = def.fields[i];
            let [fieldValue, fieldLength] = BitProcessor.getField(data.slice(offset, data.length), fieldDef["length"]) 

            let temp = ((fieldValue << offset) & 0xFFFFFFFF) >>> offset;
        }

        return returnValue;

        // return { "payload": new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF])} 
    }

    static calculateMask(len: number, offset: number) : number {
        let returnValue = 1;

        for (let i = 0; i < offset; i++) {
            returnValue |= 2 ** i;
        }

        return returnValue;
    }

    static getField(data: Uint8Array, bitLength : number) : [number, number] {
        const view = new DataView(data.buffer);

        switch ( (bitLength + (8 - (bitLength % 8))) / 8 )
        {
            case 1:
                return [view.getUint8(0), 1];
            case 2:
                return [view.getUint16(0), 2]
            case 3:
            case 4:
                return [view.getUint32(0), 4];
        }

        throw new Error("more than 32-bits requested");
    }
}