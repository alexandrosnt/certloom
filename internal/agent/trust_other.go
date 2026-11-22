//go:build !windows

package agent

func newWinTrust() winTrustHost { return nil }
