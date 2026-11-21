package workflow

import (
	"encoding/base64"
	"net"
)

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func netListen(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }
