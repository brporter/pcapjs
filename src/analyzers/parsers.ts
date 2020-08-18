
export interface IParser<T> {
    parse(data : Uint8Array) : IParserResult<T>
}

export interface IParserResult<T> {
    getResult() : T
}