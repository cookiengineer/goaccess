package snmp

import (
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Client provides SNMP communication with a target device.
// Embed this struct into exploit modules that use SNMP for information gathering.
type Client struct {
	Target    string
	Port      int
	Community string
	Timeout   time.Duration
	Verbose   bool

	snmpHandle *gosnmp.GoSNMP
}

// NewClient creates an SNMP client with sensible defaults.
func NewClient() *Client {
	return &Client{
		Port:      161,
		Community: "public",
		Timeout:   5 * time.Second,
	}
}

// Connect establishes SNMP parameters. SNMP is connectionless so this
// just initializes the internal handle.
func (client *Client) connect() {
	client.snmpHandle = &gosnmp.GoSNMP{
		Target:    client.Target,
		Port:      uint16(client.Port),
		Community: client.Community,
		Version:   gosnmp.Version2c,
		Timeout:   client.Timeout,
	}
}

// ensureHandle initializes the SNMP handle if not already set.
func (client *Client) ensureHandle() {
	if client.snmpHandle == nil {
		client.connect()
	}
}

// Get retrieves the value of a single SNMP OID.
func (client *Client) Get(oid string) (string, error) {
	client.ensureHandle()

	result, err := client.snmpHandle.Get([]string{oid})
	if err != nil {
		return "", fmt.Errorf("snmp: get %s failed: %w", oid, err)
	}

	for _, variable := range result.Variables {
		if variable.Name == oid {
			return formatSNMPValue(variable), nil
		}
	}

	return "", fmt.Errorf("snmp: OID %s not found in response", oid)
}

// Walk performs an SNMP walk starting from the given OID.
func (client *Client) Walk(oid string) (map[string]string, error) {
	client.ensureHandle()

	results, err := client.snmpHandle.BulkWalkAll(oid)
	if err != nil {
		return nil, fmt.Errorf("snmp: walk %s failed: %w", oid, err)
	}

	values := make(map[string]string, len(results))
	for _, variable := range results {
		values[variable.Name] = formatSNMPValue(variable)
	}

	return values, nil
}

// TestConnect verifies that the SNMP service is available by querying sysDescr.
func (client *Client) TestConnect() (bool, error) {
	sysDescr, err := client.Get("1.3.6.1.2.1.1.1.0")
	if err != nil {
		return false, nil
	}
	return sysDescr != "", nil
}

func formatSNMPValue(variable gosnmp.SnmpPDU) string {
	switch variable.Type {
	case gosnmp.OctetString:
		return string(variable.Value.([]byte))
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks:
		return fmt.Sprintf("%d", variable.Value)
	case gosnmp.IPAddress:
		return variable.Value.(string)
	default:
		return fmt.Sprintf("%v", variable.Value)
	}
}
