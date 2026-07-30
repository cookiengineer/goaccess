package vtwo_sdk

import (
	"encoding/binary"
	"fmt"
)

const (
	MagicBytes  uint32 = 0x56544F57
	HeaderSize  int    = 12
	TLVTypeSize int    = 1
	TLVLenSize  int    = 2
	MaxPayload  int    = 65535
)

type MessageType byte

const (
	MsgSessionInit   MessageType = 0x01
	MsgSessionAck    MessageType = 0x02
	MsgFilePushReq   MessageType = 0x10
	MsgFilePushData  MessageType = 0x11
	MsgFilePullReq   MessageType = 0x12
	MsgFilePullData  MessageType = 0x13
	MsgAck           MessageType = 0x80
	MsgError         MessageType = 0xFF
	MsgFileInfo      MessageType = 0x03
	MsgDataChunk     MessageType = 0x04
	MsgTransferDone  MessageType = 0x05
	MsgHeartbeat     MessageType = 0x06
	MsgSessionClose  MessageType = 0x7F
)

type PacketFlag byte

const (
	FlagNone         PacketFlag = 0x00
	FlagEncrypted    PacketFlag = 0x01
	FlagCompressed   PacketFlag = 0x02
	FlagFragment     PacketFlag = 0x04
	FlagLastFragment PacketFlag = 0x08
)

type Packet struct {
	Magic       uint32
	SessionID   uint16
	SequenceID  uint8
	Flags       PacketFlag
	PayloadLen  uint32
	TLVs        []TLV
}

type TLV struct {
	Type   MessageType
	Length uint16
	Value  []byte
}

func NewPacket(sessionID uint16, sequenceID uint8, flags PacketFlag) *Packet {
	return &Packet{
		Magic:      MagicBytes,
		SessionID:  sessionID,
		SequenceID: sequenceID,
		Flags:      flags,
	}
}

func (packet *Packet) AddTLV(messageType MessageType, value []byte) {
	packet.TLVs = append(packet.TLVs, TLV{
		Type:   messageType,
		Length: uint16(len(value)),
		Value:  value,
	})
	packet.recalcPayloadLen()
}

func (packet *Packet) AddTLVString(messageType MessageType, value string) {
	packet.AddTLV(messageType, []byte(value))
}

func (packet *Packet) AddTLVUint32(messageType MessageType, value uint32) {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, value)
	packet.AddTLV(messageType, buffer)
}

func (packet *Packet) AddTLVUint16(messageType MessageType, value uint16) {
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, value)
	packet.AddTLV(messageType, buffer)
}

func (packet *Packet) recalcPayloadLen() {
	var total uint32
	for _, tlv := range packet.TLVs {
		total += uint32(TLVTypeSize + TLVLenSize + int(tlv.Length))
	}
	packet.PayloadLen = total
}

func (packet *Packet) Marshal() []byte {
	packet.recalcPayloadLen()
	buffer := make([]byte, HeaderSize+int(packet.PayloadLen))

	binary.BigEndian.PutUint32(buffer[0:4], packet.Magic)
	binary.BigEndian.PutUint16(buffer[4:6], packet.SessionID)
	buffer[6] = packet.SequenceID
	buffer[7] = byte(packet.Flags)
	binary.BigEndian.PutUint32(buffer[8:12], packet.PayloadLen)

	offset := HeaderSize
	for _, tlv := range packet.TLVs {
		buffer[offset] = byte(tlv.Type)
		offset++
		binary.BigEndian.PutUint16(buffer[offset:offset+2], tlv.Length)
		offset += 2
		copy(buffer[offset:offset+int(tlv.Length)], tlv.Value)
		offset += int(tlv.Length)
	}

	return buffer
}

func UnmarshalPacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("packet too short: %d bytes, minimum %d", len(data), HeaderSize)
	}

	packet := &Packet{}
	packet.Magic = binary.BigEndian.Uint32(data[0:4])
	packet.SessionID = binary.BigEndian.Uint16(data[4:6])
	packet.SequenceID = data[6]
	packet.Flags = PacketFlag(data[7])
	packet.PayloadLen = binary.BigEndian.Uint32(data[8:12])

	if packet.Magic != MagicBytes {
		return nil, fmt.Errorf("invalid magic: 0x%08X, expected 0x%08X", packet.Magic, MagicBytes)
	}

	totalLen := HeaderSize + int(packet.PayloadLen)
	if len(data) < totalLen {
		return nil, fmt.Errorf("packet truncated: have %d bytes, need %d", len(data), totalLen)
	}

	offset := HeaderSize
	end := offset + int(packet.PayloadLen)
	for offset < end {
		if offset+TLVTypeSize+TLVLenSize > end {
			return nil, fmt.Errorf("TLV header truncated at offset %d", offset)
		}
		tlv := TLV{}
		tlv.Type = MessageType(data[offset])
		offset++
		tlv.Length = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		if offset+int(tlv.Length) > end {
			return nil, fmt.Errorf("TLV value truncated: type=%d, length=%d, offset=%d", tlv.Type, tlv.Length, offset)
		}
		tlv.Value = make([]byte, tlv.Length)
		copy(tlv.Value, data[offset:offset+int(tlv.Length)])
		offset += int(tlv.Length)
		packet.TLVs = append(packet.TLVs, tlv)
	}

	return packet, nil
}

func (packet *Packet) GetTLV(messageType MessageType) *TLV {
	for index := range packet.TLVs {
		if packet.TLVs[index].Type == messageType {
			return &packet.TLVs[index]
		}
	}
	return nil
}

func (packet *Packet) GetTLVString(messageType MessageType) string {
	tlv := packet.GetTLV(messageType)
	if tlv == nil {
		return ""
	}
	return string(tlv.Value)
}

func (packet *Packet) GetTLVUint32(messageType MessageType) (uint32, bool) {
	tlv := packet.GetTLV(messageType)
	if tlv == nil || len(tlv.Value) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(tlv.Value), true
}

func (packet *Packet) HasTLV(messageType MessageType) bool {
	return packet.GetTLV(messageType) != nil
}

func BuildSessionInit(sessionID uint16) *Packet {
	packet := NewPacket(sessionID, 0, FlagNone)
	packet.AddTLV(MsgSessionInit, []byte{0x01})
	return packet
}

func BuildSessionAck(sessionID uint16, ackID uint8) *Packet {
	packet := NewPacket(sessionID, ackID, FlagNone)
	packet.AddTLV(MsgSessionAck, []byte{})
	return packet
}

func BuildFilePullRequest(sessionID uint16, sequenceID uint8, remotePath string) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	packet.AddTLVString(MsgFilePullReq, remotePath)
	return packet
}

func BuildFilePushRequest(sessionID uint16, sequenceID uint8, remotePath string) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	packet.AddTLVString(MsgFilePushReq, remotePath)
	return packet
}

func BuildFilePushData(sessionID uint16, sequenceID uint8, data []byte, isLast bool) *Packet {
	flags := FlagNone
	if isLast {
		flags = FlagLastFragment
	}
	packet := NewPacket(sessionID, sequenceID, flags)
	packet.AddTLV(MsgFilePushData, data)
	return packet
}

func BuildHeartbeat(sessionID uint16, sequenceID uint8) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	packet.AddTLV(MsgHeartbeat, []byte{})
	return packet
}

func BuildSessionClose(sessionID uint16, sequenceID uint8) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	packet.AddTLV(MsgSessionClose, []byte{})
	return packet
}

func BuildAck(sessionID uint16, sequenceID uint8) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	packet.AddTLV(MsgAck, []byte{})
	return packet
}

func BuildFileInfoRequest(sessionID uint16, sequenceID uint8, remotePath string) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	packet.AddTLVString(MsgFileInfo, remotePath)
	return packet
}

func BuildMalformedOversizedArray(sessionID uint16, sequenceID uint8) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	tlv := TLV{
		Type:   MsgDataChunk,
		Length: uint16(MaxPayload),
		Value:  make([]byte, MaxPayload),
	}
	for index := range tlv.Value {
		tlv.Value[index] = 0x41
	}
	packet.TLVs = append(packet.TLVs, tlv)
	packet.recalcPayloadLen()
	return packet
}

func BuildMalformedArrayCount(sessionID uint16, sequenceID uint8, arrayCount uint32) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	packet.AddTLVUint32(MsgDataChunk, arrayCount)
	packet.AddTLV(MsgDataChunk, []byte{0x00})
	return packet
}

func BuildMalformedNegativeLength(sessionID uint16, sequenceID uint8) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	packet.PayloadLen = 0xFFFFFFFF
	return packet
}

func BuildPullFileCrash(sessionID uint16, sequenceID uint8) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	packet.AddTLVString(MsgFilePullReq, "")
	packet.AddTLV(
		MsgFilePullData,
		[]byte{
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0x00, 0x00, 0x00, 0x00,
		},
	)
	return packet
}

func BuildPushFileCrash(sessionID uint16, sequenceID uint8) *Packet {
	packet := NewPacket(sessionID, sequenceID, FlagNone)
	packet.AddTLVString(MsgFilePushReq, "")
	packet.AddTLV(
		MsgFilePushData,
		[]byte{
			0x00, 0x00, 0x00, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF,
			0x00, 0x00, 0x00, 0x00,
		},
	)
	return packet
}
