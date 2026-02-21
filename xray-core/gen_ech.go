package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/xtls/xray-core/transport/internet/tls"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run gen_ech.go <domain>")
		os.Exit(1)
	}

	domain := os.Args[1]
	// تولید کلیدها
	// KemID 0x0020 = X25519
	config, priv, err := tls.GenerateECHKeySet(1, domain, 0x0020)
	if err != nil {
		panic(err)
	}

	// آماده‌سازی برای کلاینت (ECHConfigList)
	rawConfig, _ := tls.MarshalBinary(config)
	clientData := make([]byte, 2+len(rawConfig))
	binary.BigEndian.PutUint16(clientData[0:2], uint16(len(rawConfig)))
	copy(clientData[2:], rawConfig)
	clientECH := base64.StdEncoding.EncodeToString(clientData)

	// آماده‌سازی برای سرور (Private + Public با پیشوند طول)
	serverData := make([]byte, 2+len(priv)+2+len(rawConfig))
	binary.BigEndian.PutUint16(serverData[0:2], uint16(len(priv)))
	copy(serverData[2:], priv)
	binary.BigEndian.PutUint16(serverData[2+len(priv):4+len(priv)], uint16(len(rawConfig)))
	copy(serverData[4+len(priv):], rawConfig)
	serverECH := base64.StdEncoding.EncodeToString(serverData)

	fmt.Printf("Client ech_key (ECH Config List):\n%s\n\n", clientECH)
	fmt.Printf("Server ech_key (Private Key Set):\n%s\n", serverECH)
}
