// MikroTik RouterOS backup (.backup) decoder.
//
// Parses the binary container produced by `/system backup save` and the
// internal "store" / item ("M2") serialization that holds the actual
// configuration, then exports it as structured JSON and a readable text tree.
//
// Container layout (all integers little-endian):
//
//	magic   u32          0xB1A1AC88 plaintext | 0x7291A8EF RC4-encrypted
//	length  u32          total file length
//	stores  ...          repeated until EOF
//
// Each store:
//
//	name_len u32, name
//	dir_len  u32, dir     directory: 12 bytes per record -> [id i32][size u32][pad u32]
//	data_len u32, data    records, each: [rec_len u16 (incl. these 2 bytes)]["M2"][payload]
//
// Each record payload is a sequence of properties:
//
//	[id u24][type u8][value]
//
// Property value encoding (type byte):
//
//	0x00/0x01      bool false / true            (0 bytes)
//	0x08           u32  (int or IPv4)           (4 bytes)
//	0x09           u8                           (1 byte)
//	0x10           u64                          (8 bytes)
//	0x18           128-bit / IPv6               (16 bytes)
//	0x20 / 0x21    string, u16 / u8 length prefix
//	0x28 / 0x29    nested "M2" message, u16 / u8 length prefix
//	0x30 / 0x32    raw bytes, u16 length prefix
//	0x31 / 0x33    raw bytes, u8 length prefix
//	type & 0x80    array: [count u16] followed by `count` elements of (type & 0x7f)
package main

import (
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
)

// ---------------------------------------------------------------- magic numbers

const (
	magicPlaintext uint32 = 0xB1A1AC88
	magicRC4       uint32 = 0x7291A8EF
)

// showAll, when set via -all, keeps unnamed fields that sit at their default
// (false / 0 / empty). By default those are hidden to cut noise — most of a
// record's properties are unset defaults that carry no information.
var showAll bool

// isDefaultValue reports whether a raw property value is an empty/zero default.
func isDefaultValue(v interface{}) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case uint64:
		return x == 0
	case string:
		return x == ""
	case []Property:
		return len(x) == 0
	case []interface{}:
		return len(x) == 0
	}
	return false
}

// hidden reports whether a property should be omitted from output: an unnamed
// field at its default value, unless -all was given.
func hidden(p Property) bool {
	return !showAll && p.Name == "" && isDefaultValue(p.Value)
}

func isScalar(v interface{}) bool {
	switch v.(type) {
	case bool, uint64, string:
		return true
	}
	return false
}

// pruneConstantFields drops unnamed scalar fields that hold the *same* value in
// every record of a multi-record store. Such fields are internal/structural
// defaults (e.g. an unchanging limit on every rule, or identical ethernet
// settings across every interface), not per-record configuration, so hiding
// them removes a lot of noise without guessing names. It also recurses into the
// per-record nested message. Skipped under -all.
func pruneConstantFields(b *Backup) {
	for si := range b.Stores {
		recs := b.Stores[si].Records
		if len(recs) < 3 {
			continue
		}
		lists := make([][]Property, len(recs))
		for i := range recs {
			lists[i] = recs[i].Properties
		}
		lists = pruneLists(lists)
		for i := range recs {
			recs[i].Properties = lists[i]
		}
	}
}

// pruneLists removes unnamed scalar fields that are identical across all the
// given property lists, then recurses into nested messages that occur once in
// every list. Returns the pruned lists.
func pruneLists(lists [][]Property) [][]Property {
	n := len(lists)
	if n < 3 {
		return lists
	}
	type acc struct {
		val      interface{}
		count    int
		constant bool
	}
	scal := map[string]*acc{}
	msgCount := map[string]int{}
	for _, props := range lists {
		for _, p := range props {
			if p.Name != "" {
				continue
			}
			if isScalar(p.Value) {
				if a, ok := scal[p.ID]; ok {
					a.count++
					if a.val != p.Value {
						a.constant = false
					}
				} else {
					scal[p.ID] = &acc{p.Value, 1, true}
				}
			} else if _, ok := p.Value.([]Property); ok {
				msgCount[p.ID]++
			}
		}
	}
	drop := map[string]bool{}
	for id, a := range scal {
		// An unnamed field that holds one and the same value everywhere it
		// appears (in at least 3 records) is a uniform internal default, not
		// per-record configuration.
		if a.constant && a.count >= 3 {
			drop[id] = true
		}
	}
	nested := map[string][][]Property{}
	for id, c := range msgCount {
		if c != n {
			continue
		}
		nl := make([][]Property, n)
		for i, props := range lists {
			for _, p := range props {
				if p.ID == id {
					nl[i], _ = p.Value.([]Property)
					break
				}
			}
		}
		nested[id] = pruneLists(nl)
	}
	out := make([][]Property, n)
	for i, props := range lists {
		var kept []Property
		for _, p := range props {
			if p.Name == "" && drop[p.ID] {
				continue
			}
			if np, ok := nested[p.ID]; ok {
				p.Value = np[i]
			}
			kept = append(kept, p)
		}
		out[i] = kept
	}
	return out
}

// ---------------------------------------------------------------- output model

type Property struct {
	ID    string      `json:"id"`
	Name  string      `json:"name,omitempty"`
	Type  string      `json:"type"`
	Value interface{} `json:"value,omitempty"`
	IPv4  string      `json:"ipv4,omitempty"`
	Note  string      `json:"note,omitempty"` // decoded hint: mac/ascii/ssh-key, resolved reference, etc.
}

type Record struct {
	ID         int        `json:"id"`
	Properties []Property `json:"properties"`
}

type Store struct {
	Name        string   `json:"name"`
	RecordCount int      `json:"record_count"`
	Records     []Record `json:"records,omitempty"`
}

type Backup struct {
	File         string  `json:"file"`
	Size         int     `json:"size"`
	Format       string  `json:"format"`
	Magic        string  `json:"magic"`
	DeclaredLen  int     `json:"declared_length"`
	LengthOK     bool    `json:"length_ok"`
	StoreCount   int     `json:"store_count"`
	NonEmpty     int     `json:"non_empty_stores"`
	TotalRecords int     `json:"total_records"`
	Stores       []Store `json:"stores"`
}

// propNames maps the universal RouterOS builtin property ids (the 0xfe
// namespace) to names. These apply at any nesting depth. 0xfeff20/0xfeff25 are
// the tagged-value pair RouterOS uses to store an IP prefix (address plus an
// optional prefix length); it recurs identically inside BGP peers, routes, etc.
var propNames = map[uint32]string{
	0xfe0001: ".id",
	0xfe0009: "comment",
	0xfe000a: "disabled",
	0xfe000d: ".default", // builtin/default item flag (true only on built-ins)
	0xfe0010: "name",
	0xfeff20: "address",
	0xfeff25: "prefix-length",
	// Interface (0x01xxxx) fields that appear inside the nested device message;
	// global so they resolve at depth > 0. Verified: ether13 l2mtu=1600.
	0x010064: "mtu",
	0x010065: "l2mtu",
}

// storePropNames maps store-specific property ids (the low 0x00.. namespace,
// whose meaning depends on the store) to names. Applied only to a record's
// top-level properties, never to nested sub-items, where the same id means
// something different. Conservative: only high-confidence fields are named.
var storePropNames = map[string]map[uint32]string{
	"user": {
		0x000001: "name",
		0x000005: "address",         // primary allowed-address ip
		0x000006: "netmask",         // primary allowed-address mask
		0x00000b: "group",           // group policy bitmask (resolved to group name)
		0x000010: "allowed-address", // list of allowed source subnets
		0x000020: "salt",            // 16-byte password salt
		0x000021: "password",        // one-way verifier (RouterOS v7 SRP); not reversible
	},
	"group": {
		0x000001: "name",
		0x000002: "policy", // permission bitmask
	},
	// BGP connections (/routing/bgp/connection). 0x2c2003 is constant across
	// peers (the router's own AS); 0x2c2011 varies (peer AS); the *-Outbound /
	// *-Inbound strings are filter chains; 0x2c2201/0x2c2202 nest the prefix
	// pair and the top-level local.address mirrors the local nested address.
	"r5/routing/ubgp/conn": {
		0x2c2003: "as",
		0x2c2009: "local.address",
		0x2c2011: "remote.as",
		0x2c2019: "output.filter",
		0x2c201a: "output.network",
		0x2c202a: "input.filter",
		0x2c2201: "local",
		0x2c2202: "remote",
		0x2c2208: "remote.port",
	},
	// Routes (/routing/route). scope/target-scope values (30/10) match the
	// RouterOS defaults exactly; dst-address and gateway are nested prefixes.
	"r5/routing/route": {
		0x000105: "dst-address",
		0x00010b: "target-scope",
		0x00010c: "scope",
		0x00010d: "gateway",
	},
	// Interface addresses (/ip/address): the classic address/network/netmask/
	// broadcast quad (verified e.g. 10.235.236.10 in 10.235.236.8/30).
	"net/addrs": {
		0x000001: "address",
		0x000002: "network",
		0x000003: "netmask",
		0x000004: "broadcast",
	},
	// Firewall/routing address lists (/ip/firewall/address-list): each entry is
	// stored as an inclusive [start,end] range (e.g. .96-.103 for a /29).
	// 0x0a is a unix creation timestamp; 0x09 is the (none) timeout sentinel.
	"net/address-list": {
		0x000003: "range-start",
		0x000004: "range-end",
		0x000009: "timeout",
		0x00000a: "creation-time",
	},
	// Interfaces (/interface). 0x010009 and 0x010030 carry the same MAC per
	// record (configured vs. hardware).
	"net/devices": {
		0x010006: "name",
		0x010009: "mac-address",
		0x010030: "orig-mac-address",
	},
	// System identity / clock (/system identity, /system clock).
	"system": {
		0x00000c: "identity",
		0x00001a: "time-zone",
	},
	// SNMP daemon settings (/snmp). trap-community defaults to "public".
	"snmpd": {
		0x000001: "enabled",
		0x000002: "contact",
		0x000003: "location",
		0x000004: "trap-community",
		0x00001b: "src-address",
		0x00001e: "engine-id",
	},
	// SNMP communities (/snmp community): name="public", read-access=yes,
	// write-access=no, addresses=213.238.170.48 (confirmed against export).
	"snmp-communities": {
		0x000005: "name",
		0x000006: "read-access",
		0x000007: "write-access",
		0x000008: "addresses",
	},
	// DNS resolver (/ip dns). All non-default-looking fields verified against the
	// official property table (defaults: cache 2048, udp 4096, timeouts 2s/10s,
	// 100 concurrent, 20 tcp, DoH 5/50/5s); timeouts are stored in milliseconds.
	"resolver/config": {
		0x000001: "servers",
		0x000003: "allow-remote-requests",
		0x000004: "cache-size",
		0x000009: "max-udp-packet-size",
		0x00000c: "query-server-timeout",
		0x00000d: "query-total-timeout",
		0x00000e: "max-concurrent-queries",
		0x00000f: "max-concurrent-tcp-sessions",
		0x000010: "use-doh-server",
		0x000011: "verify-doh-cert",
		0x000012: "doh-max-server-connections",
		0x000013: "doh-max-concurrent-queries",
		0x000014: "doh-timeout",
	},
	// DHCP client options (/ip dhcp-client option): code 61=client-id, 12=hostname.
	"dhcp/client_options": {
		0x000001: "code",
		0x000002: "value",
	},
	"ppp/profile":  {0x000001: "name"},
	"net/ctmodule": {0x000001: "name"},
	// IPsec proposal (/ip ipsec proposal): lifetime 30m=1800s; auth/enc/pfs
	// hold algorithm enum codes.
	"ipsec/sainfo": {
		0x000001: "name",
		0x000002: "lifetime",
		0x000004: "auth-algorithms",
		0x000005: "enc-algorithms",
		0x000007: "pfs-group",
	},
	// Queue types (/queue type): all params confirmed against /export verbose
	// (red 60/50/10/20/1000, sfq 5/1514, pfifo-limit 50, pcq-* defaults).
	"net/queuetypes": {
		0x000015: "kind",
		0x000016: "name",
		0x0000c9: "pfifo-limit",
		0x00012d: "red-limit",
		0x00012e: "red-max-threshold",
		0x00012f: "red-min-threshold",
		0x000130: "red-burst",
		0x000131: "red-avg-packet",
		0x000191: "sfq-perturb",
		0x000192: "sfq-allot",
		0x0001f6: "pcq-limit",
		0x0001f7: "pcq-classifier",
		0x0001f8: "pcq-total-limit",
	},
	// Logging actions (/system logging action): target enum (0=memory,1=disk,
	// 2=echo,3=remote), memory-lines=1000, remote syslog port 514.
	"log-actions": {
		0x000001: "name",
		0x000002: "target",
		0x000003: "memory-lines",
		0x000005: "disk-lines-per-file",
		0x000008: "remote-port",
		0x000010: "disk-file-name",
	},
	// Logging rules (/system logging): topics list + referenced action.
	"log-rules": {
		0x000001: "topics",
		0x000004: "action",
	},
	// System LEDs (/system leds).
	"leds": {0x000002: "name"},
	// OpenVPN server (/interface ovpn-server server): port 1194, mtu 1500.
	"ovpn/server": {
		0x0000c9: "port",
		0x0000ca: "mtu",
		0x0000cf: "mac-address",
	},
	// DHCP server config (/ip dhcp-server config): store-leases-disk 5m=300s.
	"dhcp/server/config": {
		0x000001: "store-leases-disk",
		0x000003: "accounting",
	},
	// BGP instance (/routing bgp instance): router-id + AS (215749, which the
	// generic IP heuristic would otherwise misrender).
	"r5/routing/ubgp/inst": {
		0x2c3004: "router-id",
		0x2c3005: "as",
	},
	// IKE profile (/ip ipsec profile). enc/hash/dh-group hold algorithm enum
	// codes; lifetime=1d=86400 (would otherwise misrender as 128.81.1.0).
	"ipsec/peer_proposal": {
		0x000001: "enc-algorithm",
		0x000002: "hash-algorithm",
		0x000003: "dh-group",
		0x000005: "lifetime",
		0x000007: "nat-traversal",
		0x000008: "dpd-interval",
		0x000009: "dpd-maximum-failures",
	},
	// Bridge ports (/interface bridge port): priority 0x80=128; interface has
	// many distinct values (ports), bridge few (the bridges they join).
	"bridgeports": {
		0x000002: "priority",
		0x000003: "interface",
		0x000004: "bridge",
	},
	// Raw firewall (/ip firewall raw): action 0=accept/3=drop, protocol
	// 6=tcp/17=udp, in-interface ref, address ranges, src/dst address-lists
	// (all confirmed by aligning records with /export verbose).
	"net/ipt-raw": {
		0x000001: "action",
		0x00000b: "protocol",
		0x000027: "chain",
		0x000028: "in-interface",
		0x000032: "src-address",
		0x000033: "src-address-to",
		0x000034: "dst-address",
		0x000035: "dst-address-to",
		0x000059: "src-address-list",
		0x00005a: "dst-address-list",
	},
	// Web proxy (/ip proxy): values verified against export (600/600 conns,
	// web-proxy path, dscp 4, 2048 KiB object size).
	"wproxy/config": {
		0x000001: "enabled",
		0x000005: "max-client-connections",
		0x000006: "max-server-connections",
		0x000009: "cache-administrator",
		0x00000e: "cache-path",
		0x000018: "cache-hit-dscp",
		0x00001a: "max-cache-object-size",
	},
	// Switch QoS tx-manager queues (/interface ethernet switch qos tx-manager
	// queue): schedule enum, weight 1..5, use-shared-buffers per queue.
	"net/qos/txq": {
		0x00000a: "schedule",
		0x00000b: "weight",
		0x00000d: "use-shared-buffers",
	},
	// Switch ports (/interface ethernet switch port): storm-rate default 100.
	"net/switch-ports": {0x00000f: "storm-rate"},
}

// nonIPNames are named numeric fields that are never IPv4 addresses, so the
// dotted-quad hint is suppressed for them (they are bitmasks / ids / refs).
var nonIPNames = map[string]bool{
	"policy":        true,
	"group":         true,
	".id":           true,
	"prefix-length": true,
	"as":            true, // AS numbers can look like IPs (e.g. 215749 -> 197.74.3.0)
	"remote.as":     true,
	"lifetime":      true, // durations (e.g. 86400 -> 128.81.1.0)
	"creation-time": true, // unix timestamps
	"timeout":       true,
}

// ipFieldNames are named numeric fields that always hold an IPv4 address, so
// the dotted-quad form is shown even for values the generic heuristic rejects
// (e.g. a 255.255.255.255 netmask or an x.x.x.0 network address).
var ipFieldNames = map[string]bool{
	"address":        true,
	"netmask":        true,
	"network":        true,
	"broadcast":      true,
	"local.address":  true,
	"range-start":    true,
	"range-end":      true,
	"servers":        true,
	"router-id":      true,
	"src-address":    true,
	"src-address-to": true,
	"dst-address":    true,
	"dst-address-to": true,
}

// enumNames maps a named field to the readable label for its numeric codes.
// Keyed by field name (the same field name carries the same enum across stores).
// Only mappings confirmed against /export verbose or fixed standards (IANA
// protocol numbers, DHCP option codes) are included; unlisted codes fall back to
// the raw number.
var enumNames = map[string]map[uint64]string{
	// IANA / RouterOS IP protocol numbers.
	"protocol": {
		1: "icmp", 2: "igmp", 4: "ipencap", 6: "tcp", 17: "udp", 41: "ipv6",
		46: "rsvp", 47: "gre", 50: "ipsec-esp", 51: "ipsec-ah", 58: "icmpv6",
		89: "ospf", 103: "pim", 112: "vrrp", 115: "l2tp", 132: "sctp",
	},
	// /queue type kind (derived from the 10 built-in queue types vs export).
	"kind": {2: "pfifo", 3: "red", 4: "sfq", 5: "pcq", 6: "mq-pfifo", 7: "none"},
	// /ip firewall raw action (confirmed: accept=0, drop=3).
	"action": {0: "accept", 3: "drop"},
	// /system logging action target (confirmed against export).
	"target": {0: "memory", 1: "disk", 2: "echo", 3: "remote"},
	// /ip dhcp-client option code (DHCP option numbers).
	"code": {
		12: "hostname", 51: "lease-time", 60: "vendor-class-id",
		61: "client-id", 66: "tftp-server", 67: "boot-file-name",
		121: "classless-route",
	},
	// Switch QoS tx-manager queue schedule (confirmed against export).
	"schedule": {0: "strict-priority", 1: "low-priority-group", 2: "high-priority-group"},
}

// bitmaskNames decode integer bitmask fields into a comma-separated flag list.
// The slice index is the bit position; "" marks an unused bit. The user-group
// policy map is verified against all three built-in groups (read/write/full).
var bitmaskNames = map[string][]string{
	"policy": {
		"", "local", "telnet", "ssh", "ftp", "reboot", "read", "write", "policy",
		"test", "winbox", "password", "web", "sniff", "sensitive", "api", "romon",
		"dude", "tikapp", "rest-api",
	},
	"pcq-classifier": {"src-address", "dst-address", "src-port", "dst-port"},
}

// decodeBitmask renders a bitmask field as its set flags, if the field is known.
func decodeBitmask(name string, v interface{}) (string, bool) {
	n, ok := v.(uint64)
	if !ok {
		return "", false
	}
	bits, ok := bitmaskNames[name]
	if !ok {
		return "", false
	}
	var out []string
	for i, nm := range bits {
		if nm != "" && n&(1<<uint(i)) != 0 {
			out = append(out, nm)
		}
	}
	return strings.Join(out, ","), true
}

// enumLabel returns the readable label for a named field's numeric value, if known.
func enumLabel(name string, v interface{}) (string, bool) {
	n, ok := v.(uint64)
	if !ok {
		return "", false
	}
	if m, ok := enumNames[name]; ok {
		if lbl, ok := m[n]; ok {
			return lbl, true
		}
	}
	return "", false
}

// ipv4For returns the dotted-quad rendering for a u32 property value, honoring
// the per-name overrides above.
func ipv4For(name string, v uint32) string {
	if nonIPNames[name] {
		return ""
	}
	if ipFieldNames[name] {
		return fmt.Sprintf("%d.%d.%d.%d", byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	return ipv4Hint(v)
}

// nestedPropNames names fields that live inside a store's nested message
// (depth > 0), where storePropNames (depth 0) does not apply. Used for the
// per-interface ethernet config inside net/devices.
var nestedPropNames = map[string]map[uint32]string{
	"net/devices": {
		0x0003e9: "mac-address",
		0x000404: "orig-mac-address",
		0x000419: "loop-protect-disable-time",
		0x010067: "max-l2mtu",
	},
}

// lookupName resolves a property name from the global table, then the per-store
// table (record top level, depth 0) or the nested table (depth > 0).
func lookupName(store string, depth int, id uint32) string {
	if n, ok := propNames[id]; ok {
		return n
	}
	if depth == 0 {
		if n, ok := storePropNames[store][id]; ok {
			return n
		}
	} else if n, ok := nestedPropNames[store][id]; ok {
		return n
	}
	return ""
}

// ---------------------------------------------------------------- little-endian

func u16(b []byte, i int) int    { return int(binary.LittleEndian.Uint16(b[i:])) }
func u32(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
func u24(b []byte, i int) uint32 { return uint32(b[i]) | uint32(b[i+1])<<8 | uint32(b[i+2])<<16 }
func u64(b []byte, i int) uint64 { return binary.LittleEndian.Uint64(b[i:]) }

// ---------------------------------------------------------------- entry point

func main() {
	out := flag.String("out", "output", "output file prefix (writes <prefix>.json and <prefix>.txt)")
	password := flag.String("password", "", "password for encrypted backups")
	wordlist := flag.String("wordlist", "", "audit user passwords against this wordlist file (EC-SRP5)")
	all := flag.Bool("all", false, "show all fields, including unnamed defaults (false/0/empty)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: mikrotik-backup [-out prefix] [-password pass] [-all] <backup-file>")
		flag.PrintDefaults()
	}
	flag.Parse()
	showAll = *all

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}
	file := args[0]
	prefix := *out
	if len(args) >= 2 && *out == "output" { // backwards-compatible positional prefix
		prefix = args[1]
	}

	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot read file:", err)
		os.Exit(1)
	}
	if len(data) < 8 {
		fmt.Fprintln(os.Stderr, "error: file too small to be a backup")
		os.Exit(1)
	}

	magic := u32(data, 0)
	declared := int(u32(data, 4))

	backup := Backup{
		File:        file,
		Size:        len(data),
		Magic:       fmt.Sprintf("0x%08x", magic),
		DeclaredLen: declared,
		LengthOK:    declared == len(data),
	}

	// Obtain the raw store-data section (decrypting first if necessary).
	var storeData []byte
	switch magic {
	case magicPlaintext:
		backup.Format = "plaintext"
		storeData = data[8:]
	case magicRC4:
		backup.Format = "rc4-encrypted"
		if *password == "" {
			fmt.Fprintln(os.Stderr, "error: backup is RC4-encrypted; provide -password")
			os.Exit(1)
		}
		storeData, err = decryptRC4(data[8:], *password)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr,
			"error: unrecognized magic 0x%08x.\n"+
				"This is not a plaintext or RC4 backup; newer RouterOS (>= 6.43)\n"+
				"uses AES encryption, which this tool does not decode.\n", magic)
		os.Exit(1)
	}

	backup.Stores = parseStores(storeData)
	resolveRelations(&backup)
	if !showAll {
		pruneConstantFields(&backup)
	}
	backup.StoreCount = len(backup.Stores)
	for _, s := range backup.Stores {
		if s.RecordCount > 0 {
			backup.NonEmpty++
		}
		backup.TotalRecords += s.RecordCount
	}

	// JSON export (clean, queryable shape)
	j, _ := json.MarshalIndent(buildCleanJSON(&backup), "", "  ")
	if err := os.WriteFile(prefix+".json", j, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "error writing json:", err)
		os.Exit(1)
	}
	// Text export
	if err := os.WriteFile(prefix+".txt", []byte(renderText(&backup)), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "error writing text:", err)
		os.Exit(1)
	}

	printSummary(&backup, prefix)

	// Audit passwords against an explicit -wordlist, or fall back to a
	// wordlist.txt in the working directory if one is present.
	wl := *wordlist
	if wl == "" {
		if _, err := os.Stat("wordlist.txt"); err == nil {
			wl = "wordlist.txt"
		}
	}
	if wl != "" {
		auditPasswords(&backup, wl)
	}
}

// auditPasswords recomputes each user's EC-SRP5 verifier for every candidate in
// the wordlist and reports any matches. This works only on the user's own
// backup; the verifier itself is one-way and cannot be reversed.
func auditPasswords(b *Backup, wordlistPath string) {
	data, err := os.ReadFile(wordlistPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading wordlist:", err)
		return
	}
	words := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	type cred struct {
		name     string
		salt     []byte
		verifier []byte
	}
	var creds []cred
	for _, s := range b.Stores {
		if s.Name != "user" {
			continue
		}
		for _, r := range s.Records {
			var c cred
			for _, p := range r.Properties {
				switch p.Name {
				case "name":
					c.name, _ = p.Value.(string)
				case "salt":
					c.salt = hexFieldBytes(p.Value)
				case "password":
					c.verifier = hexFieldBytes(p.Value)
				}
			}
			if c.name != "" && len(c.salt) > 0 && len(c.verifier) >= 32 {
				creds = append(creds, c)
			}
		}
	}

	fmt.Printf("\nPassword audit (EC-SRP5): %d user(s), %d candidate(s)\n", len(creds), len(words))
	for _, c := range creds {
		found := ""
		for _, w := range words {
			if w == "" {
				continue
			}
			if v := srpVerifier(c.name, w, c.salt); v != nil && bytesEqualN(v, c.verifier, 32) {
				found = w
				break
			}
		}
		if found != "" {
			fmt.Printf("  [+] %-20s : %s\n", c.name, found)
		} else {
			fmt.Printf("  [-] %-20s : not in wordlist\n", c.name)
		}
	}
}

func hexFieldBytes(v interface{}) []byte {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		return nil
	}
	return b
}

func bytesEqualN(a, b []byte, n int) bool {
	if len(a) < n || len(b) < n {
		return false
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- RC4 decryption

// decryptRC4 decrypts the body that follows the 8-byte header of an RC4
// backup. The key is SHA1(salt || password); RouterOS discards the first
// 0x300 bytes of the RC4 keystream. The result is validated by checking that
// the decrypted store section parses.
func decryptRC4(body []byte, password string) ([]byte, error) {
	if len(body) < 32 {
		return nil, fmt.Errorf("file too short for RC4 salt")
	}
	salt := body[:32]
	h := sha1.New()
	h.Write(salt)
	h.Write([]byte(password))
	cipher, err := rc4.NewCipher(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	skip := make([]byte, 0x300)
	cipher.XORKeyStream(skip, skip)

	dec := make([]byte, len(body)-32)
	cipher.XORKeyStream(dec, body[32:])

	// RouterOS prefixes the encrypted stream with a 4-byte magic check.
	if len(dec) >= 4 && looksLikeStore(dec[4:]) {
		return dec[4:], nil
	}
	if looksLikeStore(dec) {
		return dec, nil
	}
	return nil, fmt.Errorf("decryption failed (wrong password or corrupt file)")
}

// looksLikeStore reports whether b plausibly begins with a store header.
func looksLikeStore(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	n := int(u32(b, 0))
	if n <= 0 || n > 256 || 4+n > len(b) {
		return false
	}
	for _, c := range b[4 : 4+n] {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- store parsing

func parseStores(data []byte) []Store {
	var stores []Store
	i := 0
	for i+4 <= len(data) {
		nameLen := int(u32(data, i))
		if nameLen <= 0 || i+4+nameLen > len(data) {
			break // reached padding / end of meaningful data
		}
		i += 4
		name := string(data[i : i+nameLen])
		i += nameLen

		if i+4 > len(data) {
			break
		}
		dirLen := int(u32(data, i))
		i += 4
		if i+dirLen > len(data) {
			break
		}
		dir := data[i : i+dirLen]
		i += dirLen

		if i+4 > len(data) {
			break
		}
		dataLen := int(u32(data, i))
		i += 4
		if i+dataLen > len(data) {
			break
		}
		body := data[i : i+dataLen]
		i += dataLen

		stores = append(stores, parseStore(name, dir, body))
	}
	return stores
}

func parseStore(name string, dir, body []byte) Store {
	store := Store{Name: name}

	// Directory holds one [id, size, pad] entry per record.
	ids := make([]int, 0, len(dir)/12)
	for k := 0; k+12 <= len(dir); k += 12 {
		ids = append(ids, int(int32(u32(dir, k))))
	}

	j, idx := 0, 0
	for j+4 <= len(body) {
		recLen := u16(body, j)
		if recLen < 4 || j+recLen > len(body) {
			break
		}
		payload := body[j+4 : j+recLen] // skip [len u16]["M2"]
		rec := Record{ID: recordID(ids, idx), Properties: decodeProperties(payload, name, 0)}
		store.Records = append(store.Records, rec)
		j += recLen
		idx++
	}
	store.RecordCount = len(store.Records)
	return store
}

func recordID(ids []int, idx int) int {
	if idx < len(ids) {
		return ids[idx]
	}
	return idx
}

// ---------------------------------------------------------------- relations

// resolveRelations performs a second pass over the decoded stores to annotate
// cross-references that are only meaningful once every store is parsed. Today
// it links each user to its group (RouterOS stores the group's permission
// bitmask in the user record rather than a name) and flags password material.
func resolveRelations(b *Backup) {
	// Map a group's permission bitmask -> group name.
	groupByPolicy := map[uint64]string{}
	for si := range b.Stores {
		if b.Stores[si].Name != "group" {
			continue
		}
		for ri := range b.Stores[si].Records {
			var name string
			var policy uint64
			var ok bool
			for _, p := range b.Stores[si].Records[ri].Properties {
				switch p.ID {
				case "0x000001":
					name, _ = p.Value.(string)
				case "0x000002":
					policy, ok = p.Value.(uint64)
				}
			}
			if ok && name != "" {
				groupByPolicy[policy] = name
			}
		}
	}

	for si := range b.Stores {
		if b.Stores[si].Name != "user" {
			continue
		}
		for ri := range b.Stores[si].Records {
			props := b.Stores[si].Records[ri].Properties
			for pi := range props {
				switch props[pi].Name {
				case "group":
					if v, ok := props[pi].Value.(uint64); ok {
						if gn, ok := groupByPolicy[v]; ok {
							props[pi].Note = "group: " + gn
						}
					}
				case "password":
					props[pi].Note = "one-way verifier (RouterOS v7 SRP); not reversible to plaintext"
				}
			}
		}
	}
}

// ---------------------------------------------------------------- property decoding

func decodeProperties(p []byte, store string, depth int) []Property {
	var props []Property
	i := 0
	for i+4 <= len(p) {
		id := u24(p, i)
		typ := p[i+3]
		i += 4

		typeName, value, note, n := decodeValue(typ, p, i, store, depth)
		if n < 0 {
			// Unknown encoding: we cannot know the length, so emit the
			// remaining bytes verbatim and stop this record.
			props = append(props, Property{
				ID:    idString(id),
				Name:  lookupName(store, depth, id),
				Type:  fmt.Sprintf("unknown(0x%02x)", typ),
				Value: hexString(p[i:]),
			})
			break
		}

		prop := Property{ID: idString(id), Name: lookupName(store, depth, id), Type: typeName, Value: value, Note: note}
		if typ == 0x08 {
			if num, ok := value.(uint64); ok {
				prop.IPv4 = ipv4For(prop.Name, uint32(num))
			}
		}
		props = append(props, prop)
		i += n
	}
	return props
}

// decodeValue decodes a single value of the given type starting at p[i:].
// It returns a human type name, the decoded value, an optional note (a decoded
// hint such as a MAC address), and the number of bytes consumed (-1 if the
// type is not understood). store/depth are threaded so nested messages decode
// with the right naming context.
func decodeValue(typ byte, p []byte, i int, store string, depth int) (string, interface{}, string, int) {
	switch typ {
	case 0x00:
		return "bool", false, "", 0
	case 0x01:
		return "bool", true, "", 0
	case 0x09:
		if i+1 > len(p) {
			return "", nil, "", -1
		}
		return "u8", uint64(p[i]), "", 1
	case 0x08:
		if i+4 > len(p) {
			return "", nil, "", -1
		}
		return "u32", uint64(u32(p, i)), "", 4
	case 0x10:
		if i+8 > len(p) {
			return "", nil, "", -1
		}
		return "u64", u64(p, i), "", 8
	case 0x18:
		if i+16 > len(p) {
			return "", nil, "", -1
		}
		return "ip6", formatIPv6(p[i : i+16]), "", 16

	case 0x20, 0x21: // string
		raw, n := readLenPrefixed(typ, p, i)
		if n < 0 {
			return "", nil, "", -1
		}
		return "string", string(raw), "", n
	case 0x30, 0x31, 0x32, 0x33: // raw bytes
		raw, n := readLenPrefixed(typ, p, i)
		if n < 0 {
			return "", nil, "", -1
		}
		return "bytes", hexString(raw), interpretBytes(raw), n
	case 0x28, 0x29: // nested message
		raw, n := readLenPrefixed(typ, p, i)
		if n < 0 {
			return "", nil, "", -1
		}
		return "message", decodeMessage(raw, store, depth+1), "", n
	}

	if typ&0x80 != 0 { // array of (typ & 0x7f)
		base := typ & 0x7f
		if i+2 > len(p) {
			return "", nil, "", -1
		}
		count := u16(p, i)
		idx := i + 2
		items := make([]interface{}, 0, count)
		for range count {
			_, v, _, n := decodeValue(base, p, idx, store, depth+1)
			if n < 0 {
				return "", nil, "", -1
			}
			items = append(items, v)
			idx += n
		}
		return fmt.Sprintf("array[0x%02x]", base), items, "", idx - i
	}

	return "", nil, "", -1
}

// readLenPrefixed reads a u16- or u8-length-prefixed byte slice depending on
// the parity of the type code (even -> u16, odd -> u8).
func readLenPrefixed(typ byte, p []byte, i int) ([]byte, int) {
	var hdr, length int
	if typ&1 == 0 { // u16 length
		if i+2 > len(p) {
			return nil, -1
		}
		length = u16(p, i)
		hdr = 2
	} else { // u8 length
		if i+1 > len(p) {
			return nil, -1
		}
		length = int(p[i])
		hdr = 1
	}
	if i+hdr+length > len(p) {
		return nil, -1
	}
	return p[i+hdr : i+hdr+length], hdr + length
}

// decodeMessage decodes the content of a nested item. The content normally
// starts with the "M2" magic followed by properties.
func decodeMessage(content []byte, store string, depth int) []Property {
	if len(content) >= 2 && content[0] == 'M' && content[1] == '2' {
		content = content[2:]
	}
	return decodeProperties(content, store, depth)
}

// ---------------------------------------------------------------- value helpers

func idString(id uint32) string { return fmt.Sprintf("0x%06x", id) }

func hexString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hexdigits = "0123456789abcdef"
	var sb strings.Builder
	for k, c := range b {
		if k > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte(hexdigits[c>>4])
		sb.WriteByte(hexdigits[c&0xf])
	}
	return sb.String()
}

func formatIPv6(b []byte) string {
	if len(b) != 16 {
		return hexString(b)
	}
	parts := make([]string, 8)
	for k := range 8 {
		parts[k] = fmt.Sprintf("%02x%02x", b[k*2], b[k*2+1])
	}
	return strings.Join(parts, ":")
}

// interpretBytes returns a best-effort human reading of a raw byte blob, or ""
// if none applies. It recognizes MAC addresses, SSH public keys and printable
// ASCII so that otherwise opaque binaries become meaningful.
func interpretBytes(raw []byte) string {
	if len(raw) == 6 { // MAC address
		return "mac " + macString(raw)
	}
	// SSH public key wire format: [u32 len][algorithm][...]
	if len(raw) > 8 {
		l := int(binary.BigEndian.Uint32(raw[:4]))
		if l >= 4 && l <= 32 && 4+l <= len(raw) {
			alg := raw[4 : 4+l]
			if isPrintableASCII(alg) && (hasPrefix(alg, "ssh-") || hasPrefix(alg, "ecdsa-")) {
				return fmt.Sprintf("ssh public key (%s)", alg)
			}
		}
	}
	if len(raw) >= 2 && isPrintableASCII(raw) { // plain text stored as bytes
		return "ascii " + fmt.Sprintf("%q", string(raw))
	}
	return ""
}

func macString(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func hasPrefix(b []byte, s string) bool {
	return len(b) >= len(s) && string(b[:len(s)]) == s
}

// bytesReadable renders a raw blob in the most human-readable form for JSON:
// a MAC address, decoded ASCII text, an OpenSSH public-key string, or — when
// the content is genuinely binary (hashes, keys, salts) — compact hex.
func bytesReadable(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if len(raw) == 6 { // MAC address
		return macString(raw)
	}
	if len(raw) > 8 { // OpenSSH public key wire format: [u32 len][algo][...]
		l := int(binary.BigEndian.Uint32(raw[:4]))
		if l >= 4 && l <= 32 && 4+l <= len(raw) {
			alg := raw[4 : 4+l]
			if isPrintableASCII(alg) && (hasPrefix(alg, "ssh-") || hasPrefix(alg, "ecdsa-")) {
				return string(alg) + " " + base64.StdEncoding.EncodeToString(raw)
			}
		}
	}
	if isPrintableASCII(raw) { // text stored as a byte blob
		return string(raw)
	}
	return hex.EncodeToString(raw)
}

// ipv4Hint returns a dotted-quad string if the 32-bit value plausibly encodes
// an IPv4 address, else "". The bytes are taken in stored (network) order.
func ipv4Hint(v uint32) string {
	b0 := byte(v)
	b1 := byte(v >> 8)
	b2 := byte(v >> 16)
	b3 := byte(v >> 24)
	if b0 >= 1 && b0 <= 223 && (b2 != 0 || b3 != 0) {
		return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
	}
	return ""
}

// ---------------------------------------------------------------- clean JSON

// The internal model (Backup/Store/Record/Property) is faithful and typed, and
// drives the byte-level .txt export. For .json we transform it into a flatter,
// more queryable shape: empty stores collapse to a name list, and each record
// becomes a keyed map of field-name -> decoded value.

type jsonOut struct {
	File           string      `json:"file"`
	Format         string      `json:"format"`
	Magic          string      `json:"magic"`
	Size           int         `json:"size"`
	DeclaredLength int         `json:"declared_length"`
	LengthOK       bool        `json:"length_ok"`
	Summary        jsonSummary `json:"summary"`
	Stores         []jsonStore `json:"stores"`
	EmptyStores    []string    `json:"empty_stores"`
}

type jsonSummary struct {
	StoresTotal    int `json:"stores_total"`
	StoresNonEmpty int `json:"stores_non_empty"`
	Records        int `json:"records"`
}

type jsonStore struct {
	Name    string       `json:"name"`
	Records []jsonRecord `json:"records"`
}

type jsonRecord struct {
	ID     int                    `json:"id"`
	Name   string                 `json:"name,omitempty"`
	Fields map[string]interface{} `json:"fields"`
}

func buildCleanJSON(b *Backup) jsonOut {
	out := jsonOut{
		File:           b.File,
		Format:         b.Format,
		Magic:          b.Magic,
		Size:           b.Size,
		DeclaredLength: b.DeclaredLen,
		LengthOK:       b.LengthOK,
		Summary:        jsonSummary{b.StoreCount, b.NonEmpty, b.TotalRecords},
	}
	for _, s := range b.Stores {
		if s.RecordCount == 0 {
			out.EmptyStores = append(out.EmptyStores, s.Name)
			continue
		}
		js := jsonStore{Name: s.Name}
		for _, r := range s.Records {
			jr := jsonRecord{ID: r.ID, Fields: cleanFields(r.Properties)}
			for _, p := range r.Properties {
				if p.Name == "name" {
					if str, ok := p.Value.(string); ok {
						jr.Name = str
					}
					break
				}
			}
			js.Records = append(js.Records, jr)
		}
		out.Stores = append(out.Stores, js)
	}
	sort.Strings(out.EmptyStores)
	return out
}

// cleanFields turns a property list into a name->value map. Unnamed properties
// are keyed by their hex id; repeated keys collapse into an array.
func cleanFields(props []Property) map[string]interface{} {
	m := make(map[string]interface{}, len(props))
	for _, p := range props {
		if hidden(p) {
			continue
		}
		key := p.Name
		if key == "" {
			key = p.ID
		}
		v := cleanValue(p)
		if existing, ok := m[key]; ok {
			if arr, isArr := existing.([]interface{}); isArr {
				m[key] = append(arr, v)
			} else {
				m[key] = []interface{}{existing, v}
			}
			continue
		}
		m[key] = v
	}
	return m
}

// cleanValue renders a single property value as a natural JSON value: resolved
// references and IPs as strings, bytes as compact hex (MACs as colon form),
// nested messages as objects, arrays as lists.
func cleanValue(p Property) interface{} {
	switch v := p.Value.(type) {
	case []Property: // nested message
		return cleanFields(v)
	case []interface{}: // array
		out := make([]interface{}, 0, len(v))
		for _, it := range v {
			if sub, ok := it.([]Property); ok {
				out = append(out, cleanFields(sub))
			} else {
				out = append(out, it)
			}
		}
		return out
	case uint64:
		if lbl, ok := decodeBitmask(p.Name, v); ok { // flag list, e.g. policy
			return lbl
		}
		if lbl, ok := enumLabel(p.Name, v); ok { // readable enum, e.g. tcp / drop
			return lbl
		}
		if p.Note != "" { // resolved reference, e.g. group: full
			if name, ok := strings.CutPrefix(p.Note, "group: "); ok {
				return name
			}
		}
		if p.IPv4 != "" {
			return p.IPv4
		}
		return v
	case string:
		if p.Type == "bytes" {
			return bytesReadable(hexFieldBytes(v))
		}
		return v
	default:
		return v
	}
}

// ---------------------------------------------------------------- text rendering

func renderText(b *Backup) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "MikroTik RouterOS backup: %s\n", b.File)
	fmt.Fprintf(&sb, "Format: %s (magic %s)\n", b.Format, b.Magic)
	status := "OK"
	if !b.LengthOK {
		status = fmt.Sprintf("MISMATCH (file is %d bytes)", b.Size)
	}
	fmt.Fprintf(&sb, "Declared length: %d [%s]\n", b.DeclaredLen, status)
	fmt.Fprintf(&sb, "Stores: %d total, %d non-empty, %d records\n", b.StoreCount, b.NonEmpty, b.TotalRecords)
	sb.WriteString(strings.Repeat("=", 70) + "\n")

	for _, s := range b.Stores {
		if s.RecordCount == 0 {
			continue
		}
		fmt.Fprintf(&sb, "\n[%s]  (%d record(s))\n", s.Name, s.RecordCount)
		for _, rec := range s.Records {
			fmt.Fprintf(&sb, "  record #%d\n", rec.ID)
			renderProps(&sb, rec.Properties, 2)
		}
	}
	return sb.String()
}

func renderProps(sb *strings.Builder, props []Property, depth int) {
	indent := strings.Repeat("  ", depth)
	for _, p := range props {
		if hidden(p) {
			continue
		}
		label := p.Name
		if label == "" {
			label = p.ID
		}
		switch v := p.Value.(type) {
		case []Property: // nested message
			fmt.Fprintf(sb, "%s%s [%s]%s\n", indent, label, p.Type, hintSuffix(p))
			renderProps(sb, v, depth+1)
		case []interface{}: // array
			fmt.Fprintf(sb, "%s%s [%s] (%d)%s\n", indent, label, p.Type, len(v), hintSuffix(p))
			renderArray(sb, v, depth+1)
		default:
			fmt.Fprintf(sb, "%s%s [%s] = %s%s\n", indent, label, p.Type, textScalar(p), hintSuffix(p))
		}
	}
}

func renderArray(sb *strings.Builder, items []interface{}, depth int) {
	indent := strings.Repeat("  ", depth)
	for k, it := range items {
		if sub, ok := it.([]Property); ok { // array of messages
			fmt.Fprintf(sb, "%s[%d]\n", indent, k)
			renderProps(sb, sub, depth+1)
		} else {
			fmt.Fprintf(sb, "%s[%d] = %s\n", indent, k, scalarString(it))
		}
	}
}

// textScalar renders a scalar for the forensic text view, showing a decoded
// enum label alongside its raw code (e.g. "tcp (6)").
func textScalar(p Property) string {
	if lbl, ok := decodeBitmask(p.Name, p.Value); ok {
		return fmt.Sprintf("%s (%v)", lbl, p.Value)
	}
	if lbl, ok := enumLabel(p.Name, p.Value); ok {
		return fmt.Sprintf("%s (%v)", lbl, p.Value)
	}
	return scalarString(p.Value)
}

func scalarString(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return fmt.Sprintf("%q", x)
	case bool:
		return fmt.Sprintf("%t", x)
	case uint64:
		return fmt.Sprintf("%d", x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

// hintSuffix renders the IPv4 hint and/or decoded note as a trailing comment.
func hintSuffix(p Property) string {
	var parts []string
	if p.IPv4 != "" {
		parts = append(parts, "ipv4 "+p.IPv4)
	}
	if p.Note != "" {
		parts = append(parts, p.Note)
	}
	if len(parts) == 0 {
		return ""
	}
	return "  (" + strings.Join(parts, "; ") + ")"
}

// ---------------------------------------------------------------- summary

func printSummary(b *Backup, prefix string) {
	fmt.Println("MikroTik RouterOS backup decoder")
	fmt.Printf("File:   %s (%d bytes)\n", b.File, b.Size)
	status := "OK"
	if !b.LengthOK {
		status = "MISMATCH"
	}
	fmt.Printf("Format: %s (magic %s), declared length %d [%s]\n", b.Format, b.Magic, b.DeclaredLen, status)
	fmt.Printf("Stores: %d total, %d non-empty, %d records\n\n", b.StoreCount, b.NonEmpty, b.TotalRecords)

	type ns struct {
		name string
		cnt  int
	}
	var list []ns
	for _, s := range b.Stores {
		if s.RecordCount > 0 {
			list = append(list, ns{s.Name, s.RecordCount})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })

	fmt.Println("Non-empty stores:")
	for _, e := range list {
		fmt.Printf("  %-32s %d\n", e.name, e.cnt)
	}
	fmt.Printf("\nWrote %s.json and %s.txt\n", prefix, prefix)
}

// ---------------------------------------------------------------- EC-SRP5 (user credentials)
//
// RouterOS 6.45+ stores a one-way verifier, not a password:
//
//	inner = SHA256(username | ":" | password)
//	k     = SHA256(salt | inner)                  // 32-byte scalar, NOT clamped
//	(X,Y) = k * G    on Curve25519 in short-Weierstrass form
//	u     = (X + C) mod p                          // Montgomery u-coordinate
//	stored = u (32 bytes, big-endian) || (Y & 1)  // x-coordinate + y-parity byte
//
// The verifier cannot be reversed to the password; a candidate is checked by
// recomputing u and comparing. Verified against a known credential pair.

// Curve25519 as a short-Weierstrass curve y^2 = x^3 + a*x + b (b unused here).
var (
	srpP  = decBig("57896044618658097711785492504343953926634992332820282019728792003956564819949")
	srpA  = decBig("19298681539552699237261830834781317975544997444273427339909597334573241639236")
	srpGx = decBig("19298681539552699237261830834781317975544997444273427339909597334652188435546")
	srpGy = decBig("43114425171068552920764898935933967039370386198203806730763910166200978582548")
	srpC  = decBig("38597363079105398474523661669562635951089994888546854679819194669304376384412") // Weierstrass-x -> Montgomery-u
)

func decBig(s string) *big.Int { n, _ := new(big.Int).SetString(s, 10); return n }

// ptAdd adds two affine points (nil x == point at infinity).
func ptAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1 == nil {
		return x2, y2
	}
	if x2 == nil {
		return x1, y1
	}
	var lam *big.Int
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		num := new(big.Int).Mul(x1, x1)
		num.Mul(num, big.NewInt(3))
		num.Add(num, srpA)
		den := new(big.Int).Lsh(y1, 1)
		den.ModInverse(den, srpP)
		lam = num.Mul(num, den)
		lam.Mod(lam, srpP)
	} else {
		num := new(big.Int).Sub(y2, y1)
		den := new(big.Int).Sub(x2, x1)
		den.ModInverse(den, srpP)
		lam = num.Mul(num, den)
		lam.Mod(lam, srpP)
	}
	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, srpP)
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lam)
	y3.Sub(y3, y1)
	y3.Mod(y3, srpP)
	return x3, y3
}

// srpVerifier computes the 33-byte verifier (32-byte u || y-parity) for the
// given credentials.
func srpVerifier(username, password string, salt []byte) []byte {
	inner := sha256.Sum256([]byte(username + ":" + password))
	h := sha256.New()
	h.Write(salt)
	h.Write(inner[:])
	k := new(big.Int).SetBytes(h.Sum(nil)) // big-endian scalar

	var rx, ry *big.Int
	ax, ay := new(big.Int).Set(srpGx), new(big.Int).Set(srpGy)
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			rx, ry = ptAdd(rx, ry, ax, ay)
		}
		ax, ay = ptAdd(ax, ay, ax, ay)
	}
	if rx == nil {
		return nil
	}
	u := new(big.Int).Add(rx, srpC)
	u.Mod(u, srpP)

	out := make([]byte, 33)
	u.FillBytes(out[:32])
	out[32] = byte(ry.Bit(0))
	return out
}
