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

func TestAppendCRC(t *testing.T) {
	packet := []byte{0x55, 0x0E, 0x04, 0x66}
	result := AppendCRC(packet)
	if len(result) != len(packet)+2 {
		t.Errorf("expected %d bytes, got %d", len(packet)+2, len(result))
	}
}

func TestBuildUpgradePacket(t *testing.T) {
	for _, targetType := range []string{TargetAC, TargetRC, TargetGL} {
		packet := BuildUpgradePacket(targetType)
		if len(packet) < 10 {
			t.Errorf("%s upgrade packet too short: %d bytes", targetType, len(packet))
		}
		if packet[0] != MagicByte {
			t.Errorf("%s upgrade: expected magic 0x55, got 0x%02X", targetType, packet[0])
		}
		if packet[3] != CmdUpgrade {
			t.Errorf("%s upgrade: expected cmd 0xFC, got 0x%02X", targetType, packet[3])
		}
	}
}

func TestBuildReportPacket(t *testing.T) {
	for _, targetType := range []string{TargetAC, TargetRC, TargetGL} {
		packet := BuildReportPacket(targetType)
		if len(packet) < 10 {
			t.Errorf("%s report packet too short", targetType)
		}
		if packet[0] != MagicByte {
			t.Errorf("%s report: expected magic 0x55", targetType)
		}
		if packet[3] != CmdReport {
			t.Errorf("%s report: expected cmd 0x66, got 0x%02X", targetType, packet[3])
		}
	}
}

func TestBuildFileSizePacket(t *testing.T) {
	size := uint32(102157)
	for _, targetType := range []string{TargetAC, TargetRC, TargetGL} {
		packet := BuildFileSizePacket(targetType, size)
		if len(packet) < 16 {
			t.Errorf("%s filesize packet too short: %d bytes", targetType, len(packet))
		}
		if packet[0] != MagicByte {
			t.Errorf("%s filesize: expected magic 0x55", targetType)
		}
		if packet[3] != CmdFileSize {
			t.Errorf("%s filesize: expected cmd 0xB1, got 0x%02X", targetType, packet[3])
		}
	}
}

func TestBuildHashPacket(t *testing.T) {
	hash := md5.Sum([]byte("test"))
	for _, targetType := range []string{TargetAC, TargetRC, TargetGL} {
		packet := BuildHashPacket(targetType, hash[:])
		if len(packet) < 18 {
			t.Errorf("%s hash packet too short: %d bytes", targetType, len(packet))
		}
		if packet[0] != MagicByte {
			t.Errorf("%s hash: expected magic 0x55", targetType)
		}
		if packet[3] != CmdHash {
			t.Errorf("%s hash: expected cmd 0x8A, got 0x%02X", targetType, packet[3])
		}
	}
}

func TestBuildHashPacketShort(t *testing.T) {
	shortHash := make([]byte, 8)
	packet := BuildHashPacket(TargetAC, shortHash)
	if packet != nil {
		t.Error("expected nil for short hash")
	}
}

func TestBuildCleanupPacket(t *testing.T) {
	packet := BuildCleanupPacket(TargetAC)
	if len(packet) == 0 {
		t.Error("expected non-empty cleanup packet for AC")
	}
	if packet[0] != MagicByte {
		t.Error("expected magic 0x55 in cleanup")
	}
	if packet[3] != CmdCleanup {
		t.Errorf("expected cmd 0x33, got 0x%02X", packet[3])
	}

	rcPacket := BuildCleanupPacket(TargetRC)
	if rcPacket != nil {
		t.Error("expected nil cleanup for RC")
	}
}

func TestInvalidTarget(t *testing.T) {
	packet := BuildUpgradePacket("INVALID")
	if packet != nil {
		t.Error("expected nil for invalid target type")
	}
}

func TestDeviceIDMap(t *testing.T) {
	for _, targetType := range []string{TargetAC, TargetRC, TargetGL} {
		ids, ok := DeviceIDMap[targetType]
		if !ok {
			t.Errorf("expected DeviceIDMap entry for %s", targetType)
		}
		if ids.Upgrade.Source == 0 || ids.Upgrade.Target == 0 {
			t.Errorf("%s has zero device IDs", targetType)
		}
	}
}

func TestBitmaskUint32(t *testing.T) {
	value := uint32(0xDEADBEEF)
	result := BitmaskUint32(value)
	if len(result) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(result))
	}
	if result[0] != 0xDE || result[1] != 0xAD || result[2] != 0xBE || result[3] != 0xEF {
		t.Errorf("expected DE AD BE EF, got %02X %02X %02X %02X", result[0], result[1], result[2], result[3])
	}
}

func TestCRCRepeatability(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	crc1 := CalcCRC(data)
	crc2 := CalcCRC(data)
	if crc1 != crc2 {
		t.Error("CRC should be repeatable")
	}
}

func TestConstants(t *testing.T) {
	if MagicByte != 0x55 {
		t.Error("MagicByte should be 0x55")
	}
	if ProtocolVersion != 0x04 {
		t.Error("ProtocolVersion should be 0x04")
	}
	if FTPPort != 21 {
		t.Error("FTPPort should be 21")
	}
	if FTPUploadPath != "/upgrade/dji_system.bin" {
		t.Error("FTPUploadPath mismatch")
	}
}
