// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package config

const (
	Version                 = "0.1.3-rc5"
	EventizerVersion        = "network-reference-v1.4"
	AnalysisContractVersion = "xqnet-analysis-v0.2"
	MCPContractVersion      = "xqnet-mcp-v0.1"
	ProfileID               = "xq.net:profile-0.1"
	WireVersion             = "0.1"
	Modality                = "xq:network"
)

type Config struct {
	Overwrite                 bool   `json:"overwrite,omitempty"`
	Adapter                   string `json:"adapter"`
	Source                    string `json:"source"`
	NetworkID                 string `json:"network_id,omitempty"`
	NetworkCIDRs              string `json:"network_cidrs,omitempty"`
	ParquetCompression        string `json:"parquet_compression"`
	ParquetRowGroupRows       int64  `json:"parquet_row_group_rows"`
	ParquetDictionaryMaxBytes int64  `json:"parquet_dictionary_max_bytes"`
	ZeekPath                  string `json:"zeek_path,omitempty"`
	SuricataPath              string `json:"suricata_path,omitempty"`
	SuricataConfig            string `json:"suricata_config,omitempty"`
	PCAP                      bool   `json:"pcap"`
}

func Default() Config {
	return Config{
		ParquetCompression:        "zstd",
		ParquetRowGroupRows:       131072,
		ParquetDictionaryMaxBytes: 8 << 20,
	}
}
