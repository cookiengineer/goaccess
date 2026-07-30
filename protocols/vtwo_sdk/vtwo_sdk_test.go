package vtwo_sdk

import (
	"net"
	"testing"
	"time"
)

func TestNewPacket(t *testing.T) {
	packet := NewPacket(0x1234, 0x05, FlagNone)

	if packet.Magic != MagicBytes {
		t.Errorf("expected magic 0x%08X, got 0x%08X", MagicBytes, packet.Magic)
	}
	if packet.SessionID != 0x1234 {
		t.Errorf("expected session ID 0x1234, got 0x%04X", packet.SessionID)
	}
	if packet.SequenceID != 0x05 {
		t.Errorf("expected sequence ID 0x05, got 0x%02X", packet.SequenceID)
	}
	if packet.Flags != FlagNone {
		t.Errorf("expected flags 0x00, got 0x%02X", packet.Flags)
	}
}

func TestAddTLV(t *testing.T) {
	packet := NewPacket(0x0001, 0x01, FlagNone)
	packet.AddTLV(MsgSessionInit, []byte{0x01, 0x02, 0x03})

	if len(packet.TLVs) != 1 {
		t.Fatalf("expected 1 TLV, got %d", len(packet.TLVs))
	}
	if packet.TLVs[0].Type != MsgSessionInit {
		t.Errorf("expected type 0x%02X, got 0x%02X", MsgSessionInit, packet.TLVs[0].Type)
	}
	if packet.TLVs[0].Length != 3 {
		t.Errorf("expected length 3, got %d", packet.TLVs[0].Length)
	}
	if packet.PayloadLen != uint32(TLVTypeSize+TLVLenSize+3) {
		t.Errorf("expected payload len %d, got %d", TLVTypeSize+TLVLenSize+3, packet.PayloadLen)
	}
}

func TestAddTLVString(t *testing.T) {
	packet := NewPacket(0x0001, 0x01, FlagNone)
	packet.AddTLVString(MsgFilePullReq, "/test/path")

	if len(packet.TLVs) != 1 {
		t.Fatalf("expected 1 TLV, got %d", len(packet.TLVs))
	}
	value := string(packet.TLVs[0].Value)
	if value != "/test/path" {
		t.Errorf("expected '/test/path', got %q", value)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	packet := NewPacket(0x0001, 0x01, FlagNone)
	packet.AddTLV(MsgSessionInit, []byte{0x01})
	packet.AddTLVString(MsgFilePullReq, "/dcim/100media/DJI_0001.jpg")

	data := packet.Marshal()

	if len(data) < HeaderSize {
		t.Fatalf("marshaled data too short: %d bytes", len(data))
	}

	unpacked, err := UnmarshalPacket(data)
	if err != nil {
		t.Fatalf("UnmarshalPacket error: %v", err)
	}
	if unpacked.SessionID != packet.SessionID {
		t.Errorf("session ID mismatch: 0x%04X vs 0x%04X", unpacked.SessionID, packet.SessionID)
	}
	if len(unpacked.TLVs) != len(packet.TLVs) {
		t.Fatalf("TLV count mismatch: %d vs %d", len(unpacked.TLVs), len(packet.TLVs))
	}
	for index := range packet.TLVs {
		if unpacked.TLVs[index].Type != packet.TLVs[index].Type {
			t.Errorf("TLV[%d] type mismatch: 0x%02X vs 0x%02X", index, unpacked.TLVs[index].Type, packet.TLVs[index].Type)
		}
		if unpacked.TLVs[index].Length != packet.TLVs[index].Length {
			t.Errorf("TLV[%d] length mismatch: %d vs %d", index, unpacked.TLVs[index].Length, packet.TLVs[index].Length)
		}
	}
}

func TestUnmarshalInvalidMagic(t *testing.T) {
	data := make([]byte, HeaderSize)
	data[0] = 0xDE
	data[1] = 0xAD

	_, err := UnmarshalPacket(data)
	if err == nil {
		t.Error("expected error for invalid magic, got nil")
	}
}

func TestUnmarshalTooShort(t *testing.T) {
	data := make([]byte, 8)

	_, err := UnmarshalPacket(data)
	if err == nil {
		t.Error("expected error for short packet, got nil")
	}
}

func TestGetTLV(t *testing.T) {
	packet := NewPacket(0x0001, 0x01, FlagNone)
	packet.AddTLVString(MsgFilePullReq, "/test/path")
	packet.AddTLV(MsgSessionInit, []byte{0x01})

	tlv := packet.GetTLV(MsgFilePullReq)
	if tlv == nil {
		t.Fatal("expected TLV for MsgFilePullReq")
	}
	if string(tlv.Value) != "/test/path" {
		t.Errorf("expected '/test/path', got %q", string(tlv.Value))
	}

	absentTLV := packet.GetTLV(MsgError)
	if absentTLV != nil {
		t.Error("expected nil for absent TLV type")
	}
}

func TestGetTLVString(t *testing.T) {
	packet := NewPacket(0x01, 0x01, FlagNone)
	packet.AddTLVString(MsgFilePullReq, "remote_file.dat")

	value := packet.GetTLVString(MsgFilePullReq)
	if value != "remote_file.dat" {
		t.Errorf("expected 'remote_file.dat', got %q", value)
	}

	empty := packet.GetTLVString(MsgSessionAck)
	if empty != "" {
		t.Errorf("expected empty string, got %q", empty)
	}
}

func TestGetTLVUint32(t *testing.T) {
	packet := NewPacket(0x01, 0x01, FlagNone)
	packet.AddTLVUint32(MsgDataChunk, 0xDEADBEEF)

	value, ok := packet.GetTLVUint32(MsgDataChunk)
	if !ok {
		t.Fatal("expected to get uint32 from MsgDataChunk")
	}
	if value != 0xDEADBEEF {
		t.Errorf("expected 0xDEADBEEF, got 0x%08X", value)
	}

	_, ok = packet.GetTLVUint32(MsgAck)
	if ok {
		t.Error("expected false for absent TLV")
	}
}

func TestHasTLV(t *testing.T) {
	packet := NewPacket(0x01, 0x01, FlagNone)
	packet.AddTLV(MsgSessionInit, []byte{0x01})

	if !packet.HasTLV(MsgSessionInit) {
		t.Error("expected HasTLV true")
	}
	if packet.HasTLV(MsgError) {
		t.Error("expected HasTLV false")
	}
}

func TestBuildSessionInit(t *testing.T) {
	packet := BuildSessionInit(0xABCD)
	if packet.SessionID != 0xABCD {
		t.Errorf("expected session 0xABCD, got 0x%04X", packet.SessionID)
	}
	if !packet.HasTLV(MsgSessionInit) {
		t.Error("expected session init TLV")
	}
}

func TestBuildFilePullRequest(t *testing.T) {
	packet := BuildFilePullRequest(0x01, 0x02, "/test/file")
	if !packet.HasTLV(MsgFilePullReq) {
		t.Error("expected file pull request TLV")
	}
	if packet.GetTLVString(MsgFilePullReq) != "/test/file" {
		t.Errorf("expected '/test/file', got %q", packet.GetTLVString(MsgFilePullReq))
	}
}

func TestBuildMalformedPackets(t *testing.T) {
	packet := BuildMalformedOversizedArray(0x01, 0x01)
	if packet.PayloadLen == 0 {
		t.Error("expected non-zero payload for oversized array packet")
	}

	packet = BuildMalformedArrayCount(0x01, 0x01, 0xFFFFFFFF)
	if len(packet.TLVs) < 2 {
		t.Error("expected at least 2 TLVs for malformed array count packet")
	}

	packet = BuildMalformedNegativeLength(0x01, 0x01)
	if packet.PayloadLen != 0xFFFFFFFF {
		t.Errorf("expected 0xFFFFFFFF payload len, got 0x%08X", packet.PayloadLen)
	}

	packet = BuildPullFileCrash(0x01, 0x01)
	if len(packet.TLVs) < 2 {
		t.Error("expected at least 2 TLVs for pull file crash")
	}

	packet = BuildPushFileCrash(0x01, 0x01)
	if len(packet.TLVs) < 2 {
		t.Error("expected at least 2 TLVs for push file crash")
	}
}

func TestClientNewClientDefaults(t *testing.T) {
	client := NewClient()
	if client.Port != 10000 {
		t.Errorf("expected default port 10000, got %d", client.Port)
	}
	if client.Timeout == 0 {
		t.Error("expected non-zero timeout")
	}
	if client.IsConnected() {
		t.Error("expected disconnected state")
	}
	if client.IsSessionActive() {
		t.Error("expected inactive session")
	}
}

func TestClientConnectRefused(t *testing.T) {
	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = 19999
	client.Timeout = 500 * time.Millisecond

	err := client.Connect()
	if err == nil {
		client.Close()
		t.Error("expected connection error, got nil")
	}
}

func TestClientCloseNilConnection(t *testing.T) {
	client := NewClient()
	err := client.Close()
	if err != nil {
		t.Errorf("expected nil error for close on nil connection, got %v", err)
	}
}

func TestClientSendNotConnected(t *testing.T) {
	client := NewClient()
	packet := BuildSessionInit(0x01)

	err := client.SendPacket(packet)
	if err == nil {
		t.Error("expected error for send on disconnected client")
	}
}

func TestClientRecvNotConnected(t *testing.T) {
	client := NewClient()

	_, err := client.RecvPacket()
	if err == nil {
		t.Error("expected error for recv on disconnected client")
	}
}

func TestClientSessionInitNotConnected(t *testing.T) {
	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = 19999
	client.Timeout = 500 * time.Millisecond

	err := client.SessionInit()
	if err == nil {
		t.Error("expected error for session init to closed port")
	}
}

func TestClientSendAndRecvWithMockServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()

		ackPacket := BuildSessionAck(0x0001, 0x01)
		response := ackPacket.Marshal()
		connection.Write(response)

		connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 4096)
		_, _ = connection.Read(buffer)
	}()

	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = serverAddr.Port
	client.Timeout = 3 * time.Second

	err = client.Connect()
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}
	defer client.Close()

	initPacket := BuildSessionInit(0x0001)
	response, err := client.SendAndRecv(initPacket)
	if err != nil {
		t.Fatalf("SendAndRecv error: %v", err)
	}
	if response == nil {
		t.Fatal("expected non-nil response")
	}
	if !response.HasTLV(MsgSessionAck) {
		t.Error("expected session ack in response")
	}

	<-serverDone
}
