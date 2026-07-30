package duml

import (
	"crypto/md5"
	"testing"
)

func TestCalcCRC(t *testing.T) {
	data := []byte{0x55, 0x16, 0x04, 0xFC}
	crc := CalcCRC(data)
	if crc == 0 {
		t.Error("expected non-zero CRC")
	}
	twice := CalcCRC(data)
	if crc != twice {
		t.Error("CRC should be deterministic")
	}
}

func TestCalcCRCEmpty(t *testing.T) {
	crc := CalcCRC([]byte{})
	if crc != CRCSeed {
		t.Errorf("expected CRC of empty data = seed (0x%04X), got 0x%04X", CRCSeed, crc)
	}
}

func TestCalcCRCVsKnown(t *testing.T) {
	crc := CalcCRC([]byte{0x00})
	if crc == 0x0000 {
		t.Error("CRC of [0x00] should be non-zero")
	}
}

func TestCRCTableInitialValues(t *testing.T) {
	if crcTable[0] != 0x0000 {
		t.Error("crcTable[0] should be 0x0000")
	}
	if crcTable[1] != 0x1189 {
		t.Error("crcTable[1] should be 0x1189")
	}
	if crcTable[255] != 0x0F78 {
		t.Error("crcTable[255] should be 0x0F78")
	}
}

func TestAppendCRC(t *testing.T) {
	data := []byte{0x11, 0x22, 0x33}
	result := AppendCRC(data)
	if len(result) != 5 {
		t.Errorf("expected 5 bytes (3+2), got %d", len(result))
	}
	if result[0] != 0x11 || result[1] != 0x22 || result[2] != 0x33 {
		t.Error("original bytes should be preserved")
	}
	crc := CalcCRC(data)
	if result[3] != byte(crc) {
		t.Errorf("CRC LSB byte: expected 0x%02X, got 0x%02X", byte(crc), result[3])
	}
	if result[4] != byte(crc>>8) {
		t.Errorf("CRC MSB byte: expected 0x%02X, got 0x%02X", byte(crc>>8), result[4])
	}
}

func TestBuildUpgradePacket_AC(t *testing.T) {
	packet := BuildUpgradePacket(TargetAC)
	if packet == nil {
		t.Fatal("expected non-nil AC upgrade packet")
	}
	if len(packet) != 22 {
		t.Errorf("expected 22 bytes, got %d", len(packet))
	}
	if packet[0] != 0x55 {
		t.Errorf("byte[0]: expected 0x55 (magic), got 0x%02X", packet[0])
	}
	if packet[1] != 0x16 {
		t.Errorf("byte[1]: expected 0x16 (length 22), got 0x%02X", packet[1])
	}
	if packet[2] != 0x04 {
		t.Errorf("byte[2]: expected 0x04 (version), got 0x%02X", packet[2])
	}
	if packet[3] != 0xFC {
		t.Errorf("byte[3]: expected 0xFC (upgrade), got 0x%02X", packet[3])
	}
	if packet[4] != 0x2A || packet[5] != 0x28 {
		t.Errorf("bytes[4-5]: expected 0x2A 0x28 (source AC), got 0x%02X 0x%02X", packet[4], packet[5])
	}
	if packet[6] != 0x65 || packet[7] != 0x57 {
		t.Errorf("bytes[6-7]: expected 0x65 0x57 (target upgrade), got 0x%02X 0x%02X", packet[6], packet[7])
	}
	if packet[8] != 0x40 {
		t.Errorf("byte[8]: expected 0x40 (flags), got 0x%02X", packet[8])
	}
	if packet[9] != 0x00 || packet[10] != 0x07 {
		t.Errorf("bytes[9-10]: expected 0x00 0x07 (sub-cmd), got 0x%02X 0x%02X", packet[9], packet[10])
	}
	if packet[11] != 0x00 {
		t.Errorf("byte[11]: expected 0x00, got 0x%02X", packet[11])
	}
	for index := 12; index < 20; index++ {
		if packet[index] != 0x00 {
			t.Errorf("byte[%d]: expected 0x00 (padding), got 0x%02X", index, packet[index])
		}
	}
	crc := CalcCRC(packet[:20])
	expectedLSB := byte(crc)
	expectedMSB := byte(crc >> 8)
	if packet[20] != expectedLSB || packet[21] != expectedMSB {
		t.Errorf("CRC mismatch: have [0x%02X, 0x%02X], want [0x%02X, 0x%02X]",
			packet[20], packet[21], expectedLSB, expectedMSB)
	}
}

func TestBuildUpgradePacket_RC_GL(t *testing.T) {
	for _, target := range []string{TargetRC, TargetGL} {
		packet := BuildUpgradePacket(target)
		if packet == nil {
			t.Fatalf("expected non-nil packet for %s", target)
		}
		if packet[0] != 0x55 {
			t.Errorf("%s: bad magic", target)
		}
		if packet[3] != 0xFC {
			t.Errorf("%s: bad command", target)
		}
	}
}

func TestBuildReportPacket_AC(t *testing.T) {
	packet := BuildReportPacket(TargetAC)
	if packet == nil {
		t.Fatal("expected non-nil AC report packet")
	}
	if len(packet) != 14 {
		t.Errorf("expected 14 bytes, got %d", len(packet))
	}
	if packet[0] != 0x55 || packet[1] != 0x0E || packet[2] != 0x04 || packet[3] != 0x66 {
		t.Errorf("header: expected 55 0E 04 66, got %02X %02X %02X %02X",
			packet[0], packet[1], packet[2], packet[3])
	}
	if packet[4] != 0x2A || packet[5] != 0x28 {
		t.Errorf("source: expected 0x2A 0x28, got 0x%02X 0x%02X", packet[4], packet[5])
	}
	if packet[6] != 0x68 || packet[7] != 0x57 {
		t.Errorf("target: expected 0x68 0x57, got 0x%02X 0x%02X", packet[6], packet[7])
	}
	if packet[8] != 0x40 || packet[9] != 0x00 || packet[10] != 0x0C || packet[11] != 0x00 {
		t.Errorf("flags/sub: expected 40 00 0C 00, got %02X %02X %02X %02X",
			packet[8], packet[9], packet[10], packet[11])
	}
}

func TestBuildReportPacket_RC(t *testing.T) {
	packet := BuildReportPacket(TargetRC)
	if packet == nil {
		t.Fatal("expected non-nil RC report packet")
	}
	if packet[4] != 0x2A || packet[5] != 0x2D {
		t.Errorf("RC source: expected 0x2A 0x2D, got 0x%02X 0x%02X", packet[4], packet[5])
	}
	if packet[6] != 0xEA || packet[7] != 0x27 {
		t.Errorf("RC target: expected 0xEA 0x27, got 0x%02X 0x%02X", packet[6], packet[7])
	}
}

func TestBuildReportPacket_GL(t *testing.T) {
	packet := BuildReportPacket(TargetGL)
	if packet == nil {
		t.Fatal("expected non-nil GL report packet")
	}
	if packet[4] != 0x2A || packet[5] != 0x3C {
		t.Errorf("GL source: expected 0x2A 0x3C, got 0x%02X 0x%02X", packet[4], packet[5])
	}
	if packet[6] != 0xFA || packet[7] != 0x35 {
		t.Errorf("GL target: expected 0xFA 0x35, got 0x%02X 0x%02X", packet[6], packet[7])
	}
}

func TestBuildFileSizePacket_AC(t *testing.T) {
	fileSize := uint32(102157)
	packet := BuildFileSizePacket(TargetAC, fileSize)
	if packet == nil {
		t.Fatal("expected non-nil AC filesize packet")
	}
	if len(packet) != 26 {
		t.Errorf("expected 26 bytes (24+2 CRC), got %d", len(packet))
	}
	if packet[0] != 0x55 || packet[1] != 0x1A || packet[2] != 0x04 || packet[3] != 0xB1 {
		t.Errorf("header: expected 55 1A 04 B1, got %02X %02X %02X %02X",
			packet[0], packet[1], packet[2], packet[3])
	}
	if packet[4] != 0x2A || packet[5] != 0x28 {
		t.Errorf("source: expected 2A 28, got %02X %02X", packet[4], packet[5])
	}
	if packet[6] != 0x6B || packet[7] != 0x57 {
		t.Errorf("target: expected 6B 57, got %02X %02X", packet[6], packet[7])
	}
	expectedSize := []byte{0x0D, 0x8F, 0x01, 0x00}
	for index := 0; index < 4; index++ {
		if packet[12+index] != expectedSize[index] {
			t.Errorf("byte[%d] (fileSize LE): expected 0x%02X, got 0x%02X",
				12+index, expectedSize[index], packet[12+index])
		}
	}
	if packet[22] != 0x02 || packet[23] != 0x04 {
		t.Errorf("trailer: expected 02 04, got %02X %02X", packet[22], packet[23])
	}
}

func TestBuildFileSizePacket_LittleEndian(t *testing.T) {
	fileSize := uint32(0x01020304 & 0xFFFFFFFF)
	packet := BuildFileSizePacket(TargetAC, fileSize)
	if packet[12] != 0x04 || packet[13] != 0x03 || packet[14] != 0x02 || packet[15] != 0x01 {
		t.Errorf("file size 0x01020304: expected LE bytes [04 03 02 01], got [%02X %02X %02X %02X]",
			packet[12], packet[13], packet[14], packet[15])
	}
}

func TestBuildFileSizePacket_RC(t *testing.T) {
	packet := BuildFileSizePacket(TargetRC, 100)
	if packet == nil {
		t.Fatal("expected non-nil RC filesize packet")
	}
	if packet[4] != 0x2A || packet[5] != 0x2D {
		t.Errorf("RC source: expected 2A 2D, got %02X %02X", packet[4], packet[5])
	}
	if packet[6] != 0xEC || packet[7] != 0x27 {
		t.Errorf("RC target: expected EC 27, got %02X %02X", packet[6], packet[7])
	}
}

func TestBuildFileSizePacket_GL(t *testing.T) {
	packet := BuildFileSizePacket(TargetGL, 100)
	if packet == nil {
		t.Fatal("expected non-nil GL filesize packet")
	}
	if packet[4] != 0x2A || packet[5] != 0x3C {
		t.Errorf("GL source: expected 2A 3C, got %02X %02X", packet[4], packet[5])
	}
	if packet[6] != 0xFD || packet[7] != 0x35 {
		t.Errorf("GL target: expected FD 35, got %02X %02X", packet[6], packet[7])
	}
}

func TestBuildHashPacket_AC(t *testing.T) {
	testData := []byte("DUMLRacer test payload")
	hash := md5.Sum(testData)
	packet := BuildHashPacket(TargetAC, hash[:])
	if packet == nil {
		t.Fatal("expected non-nil AC hash packet")
	}
	if len(packet) != 30 {
		t.Errorf("expected 30 bytes (28+2 CRC), got %d", len(packet))
	}
	if packet[0] != 0x55 || packet[1] != 0x1E || packet[2] != 0x04 || packet[3] != 0x8A {
		t.Errorf("header: expected 55 1E 04 8A, got %02X %02X %02X %02X",
			packet[0], packet[1], packet[2], packet[3])
	}
	if packet[4] != 0x2A || packet[5] != 0x28 {
		t.Errorf("source: expected 2A 28, got %02X %02X", packet[4], packet[5])
	}
	if packet[6] != 0xF6 || packet[7] != 0x57 {
		t.Errorf("target: expected F6 57, got %02X %02X", packet[6], packet[7])
	}
	for index := 0; index < 16; index++ {
		if packet[12+index] != hash[index] {
			t.Errorf("hash byte[%d]: expected 0x%02X, got 0x%02X", index, hash[index], packet[12+index])
		}
	}
	crc := CalcCRC(packet[:28])
	expectedLSB := byte(crc)
	expectedMSB := byte(crc >> 8)
	if packet[28] != expectedLSB || packet[29] != expectedMSB {
		t.Errorf("CRC after hash: have [0x%02X, 0x%02X], want [0x%02X, 0x%02X]",
			packet[28], packet[29], expectedLSB, expectedMSB)
	}
}

func TestBuildHashPacket_RC(t *testing.T) {
	hash := md5.Sum([]byte("test"))
	packet := BuildHashPacket(TargetRC, hash[:])
	if packet == nil {
		t.Fatal("expected non-nil RC hash packet")
	}
	if packet[4] != 0x2A || packet[5] != 0x2D {
		t.Errorf("RC source: expected 2A 2D, got %02X %02X", packet[4], packet[5])
	}
	if packet[6] != 0x02 || packet[7] != 0x28 {
		t.Errorf("RC target: expected 02 28, got %02X %02X", packet[6], packet[7])
	}
}

func TestBuildHashPacket_GL(t *testing.T) {
	hash := md5.Sum([]byte("test"))
	packet := BuildHashPacket(TargetGL, hash[:])
	if packet == nil {
		t.Fatal("expected non-nil GL hash packet")
	}
	if packet[4] != 0x2A || packet[5] != 0x3C {
		t.Errorf("GL source: expected 2A 3C, got %02X %02X", packet[4], packet[5])
	}
	if packet[6] != 0x5B || packet[7] != 0x36 {
		t.Errorf("GL target: expected 5B 36, got %02X %02X", packet[6], packet[7])
	}
}

func TestBuildHashPacketShort(t *testing.T) {
	shortHash := make([]byte, 8)
	packet := BuildHashPacket(TargetAC, shortHash)
	if packet != nil {
		t.Error("expected nil for hash < 16 bytes")
	}
}

func TestBuildCleanupPacket(t *testing.T) {
	packet := BuildCleanupPacket(TargetAC)
	if packet == nil {
		t.Fatal("expected non-nil AC cleanup packet")
	}
	javaReference := []byte{
		0x55, 0x0D, 0x04, 0x33,
		0x2A, 0x28, 0x68, 0x57,
		0x00, 0x00, 0x0A, 0xF0, 0x3C,
	}
	if len(packet) != len(javaReference) {
		t.Errorf("expected %d bytes, got %d", len(javaReference), len(packet))
	}
	for index := range javaReference {
		if packet[index] != javaReference[index] {
			t.Errorf("byte[%d]: expected 0x%02X, got 0x%02X (Java ref: 0x%02X)",
				index, javaReference[index], packet[index], javaReference[index])
		}
	}
}

func TestBuildCleanupPacket_RC_GL_Nil(t *testing.T) {
	if pkt := BuildCleanupPacket(TargetRC); pkt != nil {
		t.Error("cleanup packet should be nil for RC")
	}
	if pkt := BuildCleanupPacket(TargetGL); pkt != nil {
		t.Error("cleanup packet should be nil for GL")
	}
}

func TestInvalidTarget(t *testing.T) {
	if packet := BuildUpgradePacket("INVALID"); packet != nil {
		t.Error("expected nil for invalid target type")
	}
	if packet := BuildReportPacket(""); packet != nil {
		t.Error("expected nil for empty target")
	}
	if packet := BuildFileSizePacket("BOB", 100); packet != nil {
		t.Error("expected nil for invalid target on filesize")
	}
	if packet := BuildHashPacket("NOPE", make([]byte, 16)); packet != nil {
		t.Error("expected nil for invalid target on hash")
	}
}

func TestDeviceIDMapKeys(t *testing.T) {
	for _, targetType := range []string{TargetAC, TargetRC, TargetGL} {
		ids, ok := DeviceIDMap[targetType]
		if !ok {
			t.Errorf("expected DeviceIDMap entry for %s", targetType)
		}
		if ids.Upgrade.Source == 0 || ids.Upgrade.Target == 0 {
			t.Errorf("%s has zero device IDs", targetType)
		}
	}
	if _, ok := DeviceIDMap["XY"]; ok {
		t.Error("unexpected key 'XY' in DeviceIDMap")
	}
}

func TestDeviceIDMapACValues(t *testing.T) {
	ac := DeviceIDMap[TargetAC]
	if ac.Upgrade.Source != 0x2A28 {
		t.Errorf("AC upgrade source: expected 0x2A28, got 0x%04X", ac.Upgrade.Source)
	}
	if ac.Upgrade.Target != 0x6557 {
		t.Errorf("AC upgrade target: expected 0x6557, got 0x%04X", ac.Upgrade.Target)
	}
	if ac.Report.Source != 0x2A28 {
		t.Errorf("AC report source: expected 0x2A28, got 0x%04X", ac.Report.Source)
	}
	if ac.Report.Target != 0x6857 {
		t.Errorf("AC report target: expected 0x6857, got 0x%04X", ac.Report.Target)
	}
	if ac.FileSize.Source != 0x2A28 {
		t.Errorf("AC filesize source: expected 0x2A28, got 0x%04X", ac.FileSize.Source)
	}
	if ac.FileSize.Target != 0x6B57 {
		t.Errorf("AC filesize target: expected 0x6B57, got 0x%04X", ac.FileSize.Target)
	}
	if ac.Hash.Source != 0x2A28 {
		t.Errorf("AC hash source: expected 0x2A28, got 0x%04X", ac.Hash.Source)
	}
	if ac.Hash.Target != 0xF657 {
		t.Errorf("AC hash target: expected 0xF657, got 0x%04X", ac.Hash.Target)
	}
}

func TestDeviceIDMapRCValues(t *testing.T) {
	rc := DeviceIDMap[TargetRC]
	if rc.Upgrade.Source != 0x2A2D || rc.Upgrade.Target != 0xE727 {
		t.Error("RC upgrade IDs wrong")
	}
	if rc.Report.Source != 0x2A2D || rc.Report.Target != 0xEA27 {
		t.Error("RC report IDs wrong")
	}
}

func TestDeviceIDMapGLValues(t *testing.T) {
	gl := DeviceIDMap[TargetGL]
	if gl.Upgrade.Source != 0x2A3C || gl.Upgrade.Target != 0xF735 {
		t.Error("GL upgrade IDs wrong")
	}
	if gl.Report.Source != 0x2A3C || gl.Report.Target != 0xFA35 {
		t.Error("GL report IDs wrong")
	}
}

func TestBitmaskUint32(t *testing.T) {
	value := uint32(0xDEADBEEF)
	result := BitmaskUint32(value)
	if len(result) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(result))
	}
	if result[0] != 0xDE || result[1] != 0xAD || result[2] != 0xBE || result[3] != 0xEF {
		t.Errorf("expected DE AD BE EF, got %02X %02X %02X %02X",
			result[0], result[1], result[2], result[3])
	}
}

func TestCRCRepeatability(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	if CalcCRC(data) != CalcCRC(data) {
		t.Error("CRC should be repeatable")
	}
}

func TestCRCJavaPackets(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		crcLSB uint8
		crcMSB uint8
	}{
		{
			"AC upgrade first 20 bytes",
			[]byte{0x55, 0x16, 0x04, 0xFC, 0x2A, 0x28, 0x65, 0x57, 0x40, 0x00,
				0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			0x27, 0xD3,
		},
		{
			"RC upgrade first 20 bytes",
			[]byte{0x55, 0x16, 0x04, 0xFC, 0x2A, 0x2D, 0xE7, 0x27, 0x40, 0x00,
				0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			0x9F, 0x44,
		},
		{
			"GL upgrade first 20 bytes",
			[]byte{0x55, 0x16, 0x04, 0xFC, 0x2A, 0x3C, 0xF7, 0x35, 0x40, 0x00,
				0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			0x0C, 0x29,
		},
		{
			"AC report first 12 bytes",
			[]byte{0x55, 0x0E, 0x04, 0x66, 0x2A, 0x28, 0x68, 0x57, 0x40, 0x00, 0x0C, 0x00},
			0x88, 0x20,
		},
		{
			"RC report first 12 bytes",
			[]byte{0x55, 0x0E, 0x04, 0x66, 0x2A, 0x2D, 0xEA, 0x27, 0x40, 0x00, 0x0C, 0x00},
			0x2C, 0xC8,
		},
		{
			"GL report first 12 bytes",
			[]byte{0x55, 0x0E, 0x04, 0x66, 0x2A, 0x3C, 0xFA, 0x35, 0x40, 0x00, 0x0C, 0x00},
			0x48, 0x02,
		},
	}

	for _, test := range tests {
		crc := CalcCRC(test.packet)
		gotLSB := byte(crc)
		gotMSB := byte(crc >> 8)
		if gotLSB != test.crcLSB || gotMSB != test.crcMSB {
			t.Errorf("%s: CRC mismatch. Have LSB=0x%02X MSB=0x%02X (0x%04X), want LSB=0x%02X MSB=0x%02X",
				test.name, gotLSB, gotMSB, crc, test.crcLSB, test.crcMSB)
		}
	}
}

func TestCRCFirstTwentyBytesMatchJavaReference(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		javaLSB byte
		javaMSB byte
	}{
		{
			"AC upgrade CRC",
			[]byte{0x55, 0x16, 0x04, 0xFC, 0x2A, 0x28, 0x65, 0x57, 0x40, 0x00,
				0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			0x27, 0xD3,
		},
		{
			"AC report CRC",
			[]byte{0x55, 0x0E, 0x04, 0x66, 0x2A, 0x28, 0x68, 0x57, 0x40, 0x00, 0x0C, 0x00},
			0x88, 0x20,
		},
	}

	for _, test := range tests {
		crc := CalcCRC(test.packet)
		if byte(crc) != test.javaLSB || byte(crc>>8) != test.javaMSB {
			t.Errorf("%s: Go CRC=0x%04X, Java CRC=0x%02X%02X",
				test.name, crc, test.javaMSB, test.javaLSB)
		}
	}
}

func TestConstants(t *testing.T) {
	if MagicByte != 0x55 {
		t.Error("MagicByte should be 0x55")
	}
	if ProtocolVersion != 0x04 {
		t.Error("ProtocolVersion should be 0x04")
	}
	if CmdUpgrade != 0xFC {
		t.Error("CmdUpgrade should be 0xFC")
	}
	if CmdReport != 0x66 {
		t.Error("CmdReport should be 0x66")
	}
	if CmdFileSize != 0xB1 {
		t.Error("CmdFileSize should be 0xB1")
	}
	if CmdHash != 0x8A {
		t.Error("CmdHash should be 0x8A")
	}
	if CmdCleanup != 0x33 {
		t.Error("CmdCleanup should be 0x33")
	}
	if FTPPort != 21 {
		t.Error("FTPPort should be 21")
	}
	if FTPUsername != "nouser" {
		t.Error("FTPUsername should be 'nouser'")
	}
	if FTPPassword != "nopass" {
		t.Error("FTPPassword should be 'nopass'")
	}
	if FTPUploadPath != "/upgrade/dji_system.bin" {
		t.Error("FTPUploadPath mismatch")
	}
	if SignImgsPath != "/upgrade/upgrade/signimgs" {
		t.Error("SignImgsPath mismatch")
	}
}
