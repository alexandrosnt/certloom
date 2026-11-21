package agentproto

import "testing"

func TestSealedSecretIsBoundToAgentTaskAndSolver(t *testing.T) {
	priv, pub, err := NewSealKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealSecret(pub, SealInfo("agt_1", "tsk_1", "dns_1"), []byte(`{"api_token":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenSecret(priv, SealInfo("agt_1", "tsk_1", "dns_1"), sealed); err != nil || string(got) != `{"api_token":"x"}` {
		t.Fatalf("open: %q %v", got, err)
	}
	for _, info := range [][]byte{SealInfo("agt_2", "tsk_1", "dns_1"), SealInfo("agt_1", "tsk_2", "dns_1"), SealInfo("agt_1", "tsk_1", "dns_2")} {
		if _, err := OpenSecret(priv, info, sealed); err == nil {
			t.Fatalf("opened with %q", info)
		}
	}
	other, _, _ := NewSealKey()
	if _, err := OpenSecret(other, SealInfo("agt_1", "tsk_1", "dns_1"), sealed); err == nil {
		t.Fatal("opened with another agent's key")
	}
	if _, err := SealSecret([]byte("short"), nil, nil); err == nil {
		t.Fatal("sealed to an invalid key")
	}
}
