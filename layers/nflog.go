package layers

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
)

type NFLog struct {
	BaseLayer
	Family           ProtocolFamily   /* address family */
	Version          uint8            /* version */
	ResourceID       uint16           /* resource ID */
	HardwareProtocol uint16           /* hw protocol */
	NetfilterHook    uint8            /* netfilter hook */
	AddressLength    uint16           /* address length */
	Address          net.HardwareAddr /* address, up to 8 bytes */
	Seconds          uint64
	Microseconds     uint64
	Payload          []byte
}

const (
	NFULA_PACKET_HDR         = 1  /* nflog_packet_hdr_t */
	NFULA_MARK               = 2  /* packet mark from skbuff */
	NFULA_TIMESTAMP          = 3  /* nflog_timestamp_t for skbuff's time stamp */
	NFULA_IFINDEX_INDEV      = 4  /* ifindex of device on which packet received (possibly bridge group) */
	NFULA_IFINDEX_OUTDEV     = 5  /* ifindex of device on which packet transmitted (possibly bridge group) */
	NFULA_IFINDEX_PHYSINDEV  = 6  /* ifindex of physical device on which packet received (not bridge group) */
	NFULA_IFINDEX_PHYSOUTDEV = 7  /* ifindex of physical device on which packet transmitted (not bridge group) */
	NFULA_HWADDR             = 8  /* nflog_hwaddr_t for hardware address */
	NFULA_PAYLOAD            = 9  /* packet payload */
	NFULA_PREFIX             = 10 /* text string - null-terminated, count includes NUL */
	NFULA_UID                = 11 /* UID owning socket on which packet was sent/received */
	NFULA_SEQ                = 12 /* sequence number of packets on this NFLOG socket */
	NFULA_SEQ_GLOBAL         = 13 /* sequence number of pakets on all NFLOG sockets */
	NFULA_GID                = 14 /* GID owning socket on which packet was sent/received */
	NFULA_HWTYPE             = 15 /* ARPHRD_ type of skbuff's device */
	NFULA_HWHEADER           = 16 /* skbuff's MAC-layer header */
	NFULA_HWLEN              = 17 /* length of skbuff's MAC-layer header */
)

func (n *NFLog) ReadTLV(data []byte, idx int) error {
	for idx < len(data) {
		tlvLength := int(binary.LittleEndian.Uint16(data[idx : idx+2]))
		padding := (4 - tlvLength%4) % 4
		tlvType := int(binary.LittleEndian.Uint16(data[idx+2 : idx+4]))
		switch tlvType {
		case NFULA_PACKET_HDR:
			n.HardwareProtocol = binary.BigEndian.Uint16(data[idx+4 : idx+6])
			n.NetfilterHook = uint8(data[idx+6])
		case NFULA_MARK:
		case NFULA_TIMESTAMP:
			n.Seconds = binary.BigEndian.Uint64(data[idx+4 : idx+12])
			n.Microseconds = binary.BigEndian.Uint64(data[idx+12 : idx+20])
		case NFULA_IFINDEX_INDEV:
		case NFULA_IFINDEX_OUTDEV:
		case NFULA_IFINDEX_PHYSINDEV:
		case NFULA_IFINDEX_PHYSOUTDEV:
		case NFULA_HWADDR:
			n.AddressLength = binary.BigEndian.Uint16(data[idx+4 : idx+6])
			n.Address = net.HardwareAddr(data[idx+8 : idx+8+int(n.AddressLength)])
		case NFULA_PAYLOAD:
			n.Payload = data[idx+4 : idx+tlvLength]
		case NFULA_PREFIX:
		case NFULA_UID:
		case NFULA_SEQ:
		case NFULA_SEQ_GLOBAL:
		case NFULA_GID:
		case NFULA_HWTYPE:
		case NFULA_HWHEADER:
		case NFULA_HWLEN:
		default:
			return fmt.Errorf("NFLog unsupported tlv type: %d", tlvType)
		}
		idx = idx + tlvLength + padding
	}
	return nil
}

func (n *NFLog) LayerType() gopacket.LayerType { return LayerTypeNFLog }

func (n *NFLog) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointMAC, n.Address, nil)
}

func (n *NFLog) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	n.Family = ProtocolFamily(data[0])
	n.Version = uint8(data[1])
	n.ResourceID = binary.BigEndian.Uint16(data[2:4])
	n.ReadTLV(data, 4)
	n.BaseLayer = BaseLayer{data, n.Payload}
	return nil
}

func (n *NFLog) CanDecode() gopacket.LayerClass {
	return LayerTypeNFLog
}

func (n *NFLog) NextLayerType() gopacket.LayerType {
	switch n.Family {
	case ProtocolFamilyIPv4:
		return LayerTypeIPv4
	case ProtocolFamilyIPv6Linux:
		return LayerTypeIPv6
	}
	return gopacket.LayerTypePayload
}

func decodeNFLog(data []byte, p gopacket.PacketBuilder) error {
	nflog := &NFLog{}
	err := nflog.DecodeFromBytes(data, p)
	p.AddLayer(nflog)
	p.SetLinkLayer(nflog)
	if err != nil {
		return err
	}
	return p.NextDecoder(nflog.NextLayerType())
}
