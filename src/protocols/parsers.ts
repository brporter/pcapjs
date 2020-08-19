export interface IParser<T> {
    parse(data : Uint8Array) : T
}