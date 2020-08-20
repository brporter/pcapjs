import { IParser, IProtocolContainer, PayloadProtocol } from './parsers'
import { type } from 'os';
import { IPv4Packet, IPv4Parser } from './ip';

enum EtherType {
    Unknown = 0xFFFF,
    IPv4 = 0x0800,
    ARP = 0x0806,
    WakeOnLAN = 0x0842,
    AVTP = 0x22F0,
    IETFTRILLProtocol = 0x22F3,
    StreamReservationProtocol = 0x22EA,
    DECMOPRC = 0x6002,
    DECnetPhaseIV,DNARouting = 0x6003,
    DECLAT = 0x6004,
    RARP = 0x8035,
    AppleTalk = 0x809B,
    AppleTalkAddressResolutionProtocol = 0x80F3,
    IEEE8021Q = 0x8100,
    SLPP = 0x8102,
    VLACP = 0x8103,
    IPX=0x8137,
    QNXQnet = 0x8204,
    IPv6 = 0x86DD,
    EthernetFlowControl = 0x8808,
    LACP = 0x8809,
    CobraNet = 0x8819,
    MPLSunicast = 0x8847,
    MPLSmulticast = 0x8848,
    PPPoEDiscoveryStage = 0x8863,
    PPPoESessionStage = 0x8864,
    HomePlug10MME = 0x887B,
    IEEE8021X = 0x888E,
    PROFINETProtocol = 0x8892,
    SCSIoverEthernet = 0x889A,
    ATAoverEthernet = 0x88A2,
    EtherCATProtocol = 0x88A4,
    ServiceVLANTagIdentifier = 0x88A8,
    EthernetPowerlink = 0x88AB,
    GOOSE = 0x88B8,
    GSE = 0x88B9,
    SV = 0x88BA,
    MikroTikRoMON = 0x88BF,
    LinkLayerDiscoveryProtocol = 0x88CC,
    SERCOSIII = 0x88CD,
    WSMP = 0x88DC,
    MediaRedundancyProtocol = 0x88E3,
    MACsecurity = 0x88E5,
    ProviderBackboneBridges = 0x88E7,
    PrecisionTimeProtocol = 0x88F7,
    NCSI = 0x88F8,
    ParallelRedundancyProtocol = 0x88FB,
    IEEE8021agConnectivityFaultManagement = 0x8902,
    FibreChanneloverEthernet = 0x8906,
    FCoEInitializationProtocol = 0x8914,
    RDMAoverConvergedEthernet = 0x8915,
    TTEthernetProtocolControlFrame = 0x891D,
    HSR = 0x892F,
    EthernetConfigurationTestingProtocol = 0x9000,
    IEEE8021QDoubleTagging = 0x9100,
    RedundancyTag = 0xF1C1
}

const ProtocolTypeMap = new Map([
    [EtherType.Unknown , PayloadProtocol.Unknown ],
    [EtherType.IPv4 , PayloadProtocol.IPv4 ],
    [EtherType.ARP , PayloadProtocol.ARP ],
    [EtherType.WakeOnLAN , PayloadProtocol.WakeOnLAN],
    [EtherType.AVTP , PayloadProtocol.AVTP ],
    [EtherType.IETFTRILLProtocol , PayloadProtocol.IETFTRILLProtocol ],
    [EtherType.StreamReservationProtocol , PayloadProtocol.StreamReservationProtocol ],
    [EtherType.DECMOPRC , PayloadProtocol.DECMOPRC ],
    [EtherType.DECnetPhaseIV, PayloadProtocol.DECnetPhaseIV],
    [EtherType.DNARouting, PayloadProtocol.DNARouting ],
    [EtherType.DECLAT , PayloadProtocol.DECLAT ],
    [EtherType.RARP , PayloadProtocol.RARP ],
    [EtherType.AppleTalk , PayloadProtocol.AppleTalk ],
    [EtherType.AppleTalkAddressResolutionProtocol , PayloadProtocol.AppleTalkAddressResolutionProtocol ],
    [EtherType.IEEE8021Q , PayloadProtocol.IEEE8021Q ],
    [EtherType.SLPP , PayloadProtocol.SLPP ],
    [EtherType.VLACP , PayloadProtocol.VLACP ],
    [EtherType.IPX, PayloadProtocol.IPX],
    [EtherType.QNXQnet , PayloadProtocol.QNXQnet ],
    [EtherType.IPv6 , PayloadProtocol.IPv6 ],
    [EtherType.EthernetFlowControl , PayloadProtocol.EthernetFlowControl ],
    [EtherType.LACP , PayloadProtocol.LACP ],
    [EtherType.CobraNet , PayloadProtocol.CobraNet ],
    [EtherType.MPLSunicast , PayloadProtocol.MPLSunicast ],
    [EtherType.MPLSmulticast , PayloadProtocol.MPLSmulticast ],
    [EtherType.PPPoEDiscoveryStage , PayloadProtocol.PPPoEDiscoveryStage ],
    [EtherType.PPPoESessionStage , PayloadProtocol.PPPoESessionStage ],
    [EtherType.HomePlug10MME , PayloadProtocol.HomePlug10MME ],
    [EtherType.IEEE8021X , PayloadProtocol.IEEE8021X ],
    [EtherType.PROFINETProtocol , PayloadProtocol.PROFINETProtocol ],
    [EtherType.SCSIoverEthernet , PayloadProtocol.SCSIoverEthernet ],
    [EtherType.ATAoverEthernet , PayloadProtocol.ATAoverEthernet ],
    [EtherType.EtherCATProtocol , PayloadProtocol.EtherCATProtocol ],
    [EtherType.ServiceVLANTagIdentifier , PayloadProtocol.ServiceVLANTagIdentifier ],
    [EtherType.EthernetPowerlink , PayloadProtocol.EthernetPowerlink ],
    [EtherType.GOOSE , PayloadProtocol.GOOSE ],
    [EtherType.GSE , PayloadProtocol.GSE ],
    [EtherType.SV , PayloadProtocol.SV ],
    [EtherType.MikroTikRoMON , PayloadProtocol.MikroTikRoMON ],
    [EtherType.LinkLayerDiscoveryProtocol , PayloadProtocol.LinkLayerDiscoveryProtocol ],
    [EtherType.SERCOSIII , PayloadProtocol.SERCOSIII ],
    [EtherType.WSMP , PayloadProtocol.WSMP ],
    [EtherType.MediaRedundancyProtocol , PayloadProtocol.MediaRedundancyProtocol ],
    [EtherType.MACsecurity , PayloadProtocol.MACsecurity ],
    [EtherType.ProviderBackboneBridges , PayloadProtocol.ProviderBackboneBridges ],
    [EtherType.PrecisionTimeProtocol , PayloadProtocol.PrecisionTimeProtocol ],
    [EtherType.NCSI , PayloadProtocol.NCSI ],
    [EtherType.ParallelRedundancyProtocol , PayloadProtocol.ParallelRedundancyProtocol ],
    [EtherType.IEEE8021agConnectivityFaultManagement , PayloadProtocol.IEEE8021agConnectivityFaultManagement ],
    [EtherType.FibreChanneloverEthernet , PayloadProtocol.FibreChanneloverEthernet ],
    [EtherType.FCoEInitializationProtocol , PayloadProtocol.FCoEInitializationProtocol ],
    [EtherType.RDMAoverConvergedEthernet , PayloadProtocol.RDMAoverConvergedEthernet ],
    [EtherType.TTEthernetProtocolControlFrame , PayloadProtocol.TTEthernetProtocolControlFrame ],
    [EtherType.HSR , PayloadProtocol.HSR ],
    [EtherType.EthernetConfigurationTestingProtocol , PayloadProtocol.EthernetConfigurationTestingProtocol ],
    [EtherType.IEEE8021QDoubleTagging , PayloadProtocol.IEEE8021QDoubleTagging ],
    [EtherType.RedundancyTag, PayloadProtocol.RedundancyTag],
])

export class EthernetFrame implements IProtocolContainer {
    readonly destination : Uint8Array;
    readonly source : Uint8Array;
    readonly vlanTag : Uint8Array;
    readonly payload : Uint8Array;
    readonly protocol : PayloadProtocol;

    constructor(destination : Uint8Array, source : Uint8Array, vlanTag : Uint8Array, protocol : PayloadProtocol, payload : Uint8Array) {
        this.destination = destination;
        this.source = source;
        this.vlanTag = vlanTag;
        this.payload = payload;

        this.protocol = protocol
    }
}

export class EthernetParser implements IParser<EthernetFrame> {
    parse(data : Uint8Array): EthernetFrame {
        const view = new DataView(data.buffer);
        const destination = data.slice(0, 6);
        const source = data.slice(6, 12);

        const vlanTag = new Uint8Array(2);
        let payload : Uint8Array | null = null;
        let determinedType : EtherType = EtherType.Unknown;
        let rawType = view.getUint16(12, false);

        let offset = 14;

        if (rawType > 1536) {
            // if greater than 1536, this is an ether type field
            // if less, it's the length in octets of the frame
            // if the ethertype field indicates VLAN tagging, decode the VLAN tag
            determinedType = <EtherType>rawType;

            if (determinedType == EtherType.IEEE8021Q || determinedType == EtherType.ServiceVLANTagIdentifier) {
                vlanTag.set(data.slice(14, 16));
                offset = 16;
            }
        }

        payload = data.slice(offset, data.length);

        return new EthernetFrame(
            destination, 
            source, 
            vlanTag, 
            ProtocolTypeMap.get(determinedType) ?? PayloadProtocol.Unknown, 
            payload ?? new Uint8Array(0));
    }
}