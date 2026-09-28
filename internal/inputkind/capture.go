// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package inputkind

import (
	"os"
	"path/filepath"
	"strings"
)

// IsPacketCapture reports whether path should be treated as a packet capture.
// Content magic takes precedence over filename extension so captures with
// non-standard names (for example .dmp) are still recognized.
func IsPacketCapture(path string) bool {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return false
	}
	if hasPacketCaptureMagicFile(path) {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pcap", ".pcapng", ".cap", ".dmp":
		return true
	default:
		return false
	}
}

// HasPacketCaptureMagicBytes recognizes classic PCAP (microsecond and
// nanosecond, both endian forms) and PCAPNG section-header magic.
func HasPacketCaptureMagicBytes(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	m := [4]byte{b[0], b[1], b[2], b[3]}
	switch m {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1},
		[4]byte{0xa1, 0xb2, 0xc3, 0xd4},
		[4]byte{0x4d, 0x3c, 0xb2, 0xa1},
		[4]byte{0xa1, 0xb2, 0x3c, 0x4d},
		[4]byte{0x0a, 0x0d, 0x0d, 0x0a}:
		return true
	default:
		return false
	}
}

func hasPacketCaptureMagicFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var b [4]byte
	n, err := f.Read(b[:])
	if err != nil || n < len(b) {
		return false
	}
	return HasPacketCaptureMagicBytes(b[:])
}
