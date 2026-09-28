// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package inputkind

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPacketCaptureRecognizesDMPByExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.dmp")
	if err := os.WriteFile(path, []byte("not enough bytes to sniff"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !IsPacketCapture(path) {
		t.Fatal("expected .dmp to be treated as a packet capture")
	}
}

func TestIsPacketCaptureRecognizesMagicWithUnknownExtension(t *testing.T) {
	cases := map[string][]byte{
		"classic-pcap": {0xd4, 0xc3, 0xb2, 0xa1, 0, 0, 0, 0},
		"pcapng":       {0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture.bin")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if !IsPacketCapture(path) {
				t.Fatalf("expected capture magic to override unknown extension for %s", name)
			}
		})
	}
}

func TestIsPacketCaptureRejectsEVEJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte("{\"event_type\":\"flow\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if IsPacketCapture(path) {
		t.Fatal("EVE JSON must not be classified as a packet capture")
	}
}
