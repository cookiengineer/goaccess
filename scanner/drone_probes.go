package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cookiengineer/goaccess/protocols/telnet"
	"github.com/cookiengineer/goaccess/protocols/vtwo_sdk"
	"github.com/cookiengineer/goaccess/types"
)

var droneFirmwarePaths = []string{
	"/etc/version",
	"/etc/dji_version",
	"/system/build.prop",
	"/etc/os-release",
	"/proc/version",
}

var droneFirmwarePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:FW_VERSION|ro\.build\.version\.release|ro\.build\.id|VERSION_ID)\s*=\s*([0-9A-Za-z._-]+)`),
	regexp.MustCompile(`(?:DJI|Firmware|Software|version)\s*[:=v]?\s*([0-9]+\.[0-9]+\.[0-9]+)`),
	regexp.MustCompile(`(\d+\.\d+\.\d+)`),
}

func probeDroneFirmware(target string, openPorts []int, timeout time.Duration, result *types.FingerprintResult) bool {
	hasPort := func(port int) bool {
		for _, p := range openPorts {
			if p == port {
				return true
			}
		}
		return false
	}

	if hasPort(10000) {
		if fw := probeDJIFirmware(target, 10000, timeout); fw != "" {
			result.Firmware = fw
			result.Hints = append(result.Hints, fmt.Sprintf("[Drone] DJI Firmware: %s (vtwo_sdk on port 10000)", fw))
			return true
		}
	}

	if hasPort(23) {
		if fw := probeParrotFirmware(target, 23, timeout); fw != "" {
			result.Firmware = fw
			result.Hints = append(result.Hints, fmt.Sprintf("[Drone] Parrot Firmware: %s (telnet on port 23)", fw))
			return true
		}
	}

	return false
}

func probeDJIFirmware(target string, port int, timeout time.Duration) string {
	client := vtwo_sdk.NewClient()
	client.Target = target
	client.Port = port
	client.Timeout = timeout

	if err := client.Connect(); err != nil {
		return ""
	}
	defer client.Close()

	sessionID := uint16(time.Now().UnixNano() & 0xFFFF)
	initPacket := vtwo_sdk.BuildSessionInit(sessionID)
	response, err := client.SendAndRecv(initPacket)
	if err != nil || response == nil {
		return ""
	}

	ackTLV := response.GetTLV(vtwo_sdk.MsgSessionAck)
	if ackTLV == nil {
		return ""
	}

	client.SequenceID = 1

	for _, path := range droneFirmwarePaths {
		fileInfoPacket := vtwo_sdk.BuildFileInfoRequest(sessionID, client.SequenceID, path)
		resp, err := client.SendAndRecv(fileInfoPacket)
		client.SequenceID++
		if err != nil || resp == nil {
			continue
		}

		content := extractVtwoPayload(resp)
		if len(content) == 0 {
			continue
		}

		for _, pattern := range droneFirmwarePatterns {
			matches := pattern.FindStringSubmatch(string(content))
			if len(matches) >= 2 {
				return strings.TrimSpace(matches[1])
			}
		}
	}

	return ""
}

func probeParrotFirmware(target string, port int, timeout time.Duration) string {
	client := telnet.NewClient()
	client.Target = target
	client.Port = port
	client.Timeout = timeout

	if err := client.Connect(); err != nil {
		return ""
	}
	defer client.Close()

	banner, err := client.Read(4096)
	if err != nil {
		return ""
	}

	bannerStr := string(banner)
	if !strings.Contains(bannerStr, "BusyBox") && !strings.Contains(bannerStr, "buildroot") &&
		(strings.Contains(bannerStr, "ogin:") || strings.Contains(bannerStr, "assword:")) {
		return ""
	}

	for _, pattern := range droneFirmwarePatterns {
		matches := pattern.FindStringSubmatch(bannerStr)
		if len(matches) >= 2 {
			return strings.TrimSpace(matches[1])
		}
	}

	commands := []string{
		"cat /etc/version\r\n",
		"uname -a\r\n",
		"cat /etc/parrot-version 2>/dev/null\r\n",
	}

	for _, cmd := range commands {
		client.Write([]byte(cmd))
		time.Sleep(300 * time.Millisecond)
		output, err := client.Read(4096)
		if err != nil {
			continue
		}

		for _, pattern := range droneFirmwarePatterns {
			matches := pattern.FindStringSubmatch(string(output))
			if len(matches) >= 2 {
				return strings.TrimSpace(matches[1])
			}
		}
	}

	return ""
}

func extractVtwoPayload(response *vtwo_sdk.Packet) []byte {
	for msgType := byte(0x00); msgType < 0x20; msgType++ {
		tlv := response.GetTLV(vtwo_sdk.MessageType(msgType))
		if tlv != nil && len(tlv.Value) > 2 {
			return tlv.Value
		}
	}
	return nil
}
