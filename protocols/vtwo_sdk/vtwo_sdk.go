package vtwo_sdk

import (
	"fmt"
	"net"
	"time"
)

type Client struct {
	Target  string
	Port    int
	Timeout time.Duration

	connection       net.Conn
	sessionID        uint16
	SequenceID       uint8
	sessionActive    bool
}

func NewClient() *Client {
	return &Client{
		Port:    10000,
		Timeout: 8 * time.Second,
	}
}

func (client *Client) Connect() error {
	address := net.JoinHostPort(client.Target, fmt.Sprintf("%d", client.Port))
	dialer := net.Dialer{Timeout: client.Timeout}
	connection, err := dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("vtwo_sdk: connect to %s failed: %w", address, err)
	}
	client.connection = connection
	return nil
}

func (client *Client) SendPacket(packet *Packet) error {
	if client.connection == nil {
		return fmt.Errorf("vtwo_sdk: not connected")
	}
	data := packet.Marshal()
	_, err := client.connection.Write(data)
	if err != nil {
		return fmt.Errorf("vtwo_sdk: send failed: %w", err)
	}
	return nil
}

func (client *Client) RecvPacket() (*Packet, error) {
	if client.connection == nil {
		return nil, fmt.Errorf("vtwo_sdk: not connected")
	}

	headerBytes, err := client.recvAll(HeaderSize)
	if err != nil {
		return nil, fmt.Errorf("vtwo_sdk: recv header failed: %w", err)
	}

	magic := binaryMagic(headerBytes)
	if magic != MagicBytes {
		return nil, fmt.Errorf("vtwo_sdk: invalid magic 0x%08X", magic)
	}

	payloadLen := binaryPayloadLen(headerBytes)
	if payloadLen > uint32(MaxPayload) {
		return nil, fmt.Errorf("vtwo_sdk: payload too large: %d", payloadLen)
	}

	remaining := int(payloadLen)
	if remaining == 0 {
		return UnmarshalPacket(headerBytes)
	}

	payloadBytes, err := client.recvAll(remaining)
	if err != nil {
		return nil, fmt.Errorf("vtwo_sdk: recv payload failed: %w", err)
	}

	fullData := append(headerBytes, payloadBytes...)
	return UnmarshalPacket(fullData)
}

func (client *Client) SendAndRecv(packet *Packet) (*Packet, error) {
	if err := client.SendPacket(packet); err != nil {
		return nil, err
	}
	client.connection.SetReadDeadline(time.Now().Add(client.Timeout))
	return client.RecvPacket()
}

func (client *Client) SessionInit() error {
	if err := client.Connect(); err != nil {
		return err
	}

	client.sessionID = uint16(time.Now().UnixNano() & 0xFFFF)
	client.SequenceID = 0

	initPacket := BuildSessionInit(client.sessionID)
	if err := client.SendPacket(initPacket); err != nil {
		return fmt.Errorf("vtwo_sdk: session init send failed: %w", err)
	}

	client.connection.SetReadDeadline(time.Now().Add(client.Timeout))
	response, err := client.RecvPacket()
	if err != nil {
		client.sessionActive = false
		return nil
	}

	if response.HasTLV(MsgSessionAck) || response.Flags == FlagNone {
		client.sessionActive = true
		return nil
	}

	return nil
}

func (client *Client) SendRaw(data []byte) error {
	if client.connection == nil {
		return fmt.Errorf("vtwo_sdk: not connected")
	}
	_, err := client.connection.Write(data)
	if err != nil {
		return fmt.Errorf("vtwo_sdk: send raw failed: %w", err)
	}
	return nil
}

func (client *Client) RecvRaw(length int) ([]byte, error) {
	if client.connection == nil {
		return nil, fmt.Errorf("vtwo_sdk: not connected")
	}
	return client.recvAll(length)
}

func (client *Client) PullFile(remotePath string) (*Packet, error) {
	if !client.sessionActive {
		return nil, fmt.Errorf("vtwo_sdk: no active session")
	}
	client.SequenceID++
	return client.SendAndRecv(BuildFilePullRequest(client.sessionID, client.SequenceID, remotePath))
}

func (client *Client) PushFile(remotePath string, data []byte) (*Packet, error) {
	if !client.sessionActive {
		return nil, fmt.Errorf("vtwo_sdk: no active session")
	}
	client.SequenceID++
	return client.SendAndRecv(BuildFilePushRequest(client.sessionID, client.SequenceID, remotePath))
}

func (client *Client) SessionClose() error {
	if !client.sessionActive {
		return nil
	}
	client.SequenceID++
	closePacket := BuildSessionClose(client.sessionID, client.SequenceID)
	err := client.SendPacket(closePacket)
	client.sessionActive = false
	return err
}

func (client *Client) Close() error {
	if client.connection == nil {
		return nil
	}
	err := client.connection.Close()
	client.connection = nil
	client.sessionActive = false
	if err != nil {
		return fmt.Errorf("vtwo_sdk: close failed: %w", err)
	}
	return nil
}

func (client *Client) IsConnected() bool {
	return client.connection != nil
}

func (client *Client) IsSessionActive() bool {
	return client.sessionActive
}

func (client *Client) address() string {
	port := client.Port
	if port == 0 {
		port = 10000
	}
	return net.JoinHostPort(client.Target, fmt.Sprintf("%d", port))
}

func (client *Client) recvAll(length int) ([]byte, error) {
	buffer := make([]byte, length)
	totalRead := 0
	for totalRead < length {
		bytesRead, err := client.connection.Read(buffer[totalRead:])
		if err != nil {
			return nil, err
		}
		if bytesRead == 0 {
			break
		}
		totalRead += bytesRead
	}
	if totalRead == 0 {
		return nil, fmt.Errorf("connection closed")
	}
	return buffer[:totalRead], nil
}

func binaryMagic(header []byte) uint32 {
	return uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])
}

func binaryPayloadLen(header []byte) uint32 {
	return uint32(header[8])<<24 | uint32(header[9])<<16 | uint32(header[10])<<8 | uint32(header[11])
}
