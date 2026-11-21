// Package kube runs the in-cluster observation agent (ADR-0023) against a
// real kind cluster with cert-manager, using the service account and RBAC
// from deploy/kubernetes/agent.yaml. The control plane runs in-process.
//
//	CERTLOOM_KUBE_E2E=1 CERTLOOM_TEST_DATABASE_URL=... go test ./test/kube/
package kube

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agent"
	"github.com/alexandrosnt/certloom/internal/agentapi"
	"github.com/alexandrosnt/certloom/internal/agentpki"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/kek"
	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
)

const (
	kindVersion        = "v0.27.0"
	certManagerVersion = "v1.17.2"
	trustManagerCRD    = "https://raw.githubusercontent.com/cert-manager/trust-manager/v0.16.0/deploy/crds/trust.cert-manager.io_bundles.yaml"
	cluster            = "certloom-e2e"
)

var ctx = context.Background()

type kube struct {
	t          *testing.T
	kubeconfig string
}

func (k *kube) run(name string, args ...string) string {
	k.t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+k.kubeconfig)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		k.t.Fatalf("%s %s: %v\n%s%s", name, strings.Join(args, " "), err, out.String(), errb.String())
	}
	return out.String()
}

func (k *kube) kubectl(args ...string) string { return k.run("kubectl", args...) }

func (k *kube) apply(manifest string) {
	k.t.Helper()
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+k.kubeconfig)
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		k.t.Fatalf("apply: %v\n%s", err, out)
	}
}

func startCluster(t *testing.T) *kube {
	if os.Getenv("CERTLOOM_KUBE_E2E") != "1" {
		t.Skip("set CERTLOOM_KUBE_E2E=1 (needs Docker, kubectl and network)")
	}
	k := &kube{t: t, kubeconfig: filepath.Join(t.TempDir(), "kubeconfig")}
	kind := []string{"run", "sigs.k8s.io/kind@" + kindVersion}
	k.run("go", append(kind, "create", "cluster", "--name", cluster, "--kubeconfig", k.kubeconfig, "--wait", "120s")...)
	t.Cleanup(func() {
		_ = exec.Command("go", append(kind, "delete", "cluster", "--name", cluster)...).Run()
	})
	k.kubectl("apply", "-f", "https://github.com/cert-manager/cert-manager/releases/download/"+certManagerVersion+"/cert-manager.yaml")
	k.kubectl("-n", "cert-manager", "wait", "--for=condition=Available", "deployment", "--all", "--timeout=300s")
	// trust-manager itself is not installed: its CRD alone lets a Bundle
	// exist without a controller, which is a Bundle that never syncs.
	k.kubectl("apply", "-f", trustManagerCRD)
	k.kubectl("apply", "-f", filepath.Join("..", "..", "deploy", "kubernetes", "agent.yaml"))
	k.kubectl("-n", "certloom-agent", "scale", "deployment", "certloom-agent", "--replicas=0")
	return k
}

const objects = `
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: selfsigned}
spec: {selfSigned: {}}
---
apiVersion: v1
kind: Namespace
metadata: {name: web}
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata: {name: broken, namespace: web}
spec: {ca: {secretName: does-not-exist}}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: good, namespace: web}
spec:
  secretName: good-tls
  dnsNames: [good.kube.test]
  issuerRef: {name: selfsigned, kind: ClusterIssuer}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: bad, namespace: web}
spec:
  secretName: bad-tls
  dnsNames: [bad.kube.test]
  issuerRef: {name: broken}
---
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata: {name: trust}
spec:
  sources: [{useDefaultCAs: true}]
  target: {configMap: {key: ca.crt}}
`

func TestObserveCertManager(t *testing.T) {
	k := startCluster(t)
	k.apply(objects)
	k.kubectl("-n", "web", "wait", "--for=condition=Ready", "certificate/good", "--timeout=120s")

	sa := "system:serviceaccount:certloom-agent:certloom-agent"
	for _, check := range [][]string{{"get", "secrets"}, {"list", "configmaps"}, {"update", "certificates.cert-manager.io"}} {
		out, _ := exec.Command("kubectl", "--kubeconfig", k.kubeconfig, "auth", "can-i", check[0], check[1], "--all-namespaces", "--as", sa).Output()
		if strings.TrimSpace(string(out)) != "no" {
			t.Fatalf("agent service account may %s %s", check[0], check[1])
		}
	}

	// Credentials as the pod would see them: a token for the agent's
	// service account and the cluster CA.
	dir := t.TempDir()
	token := k.kubectl("-n", "certloom-agent", "create", "token", "certloom-agent", "--duration=1h")
	caB64 := k.kubectl("config", "view", "--raw", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	server := strings.TrimSpace(k.kubectl("config", "view", "--raw", "-o", "jsonpath={.clusters[0].cluster.server}"))
	ca, err := base64.StdEncoding.DecodeString(caB64)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "token"), []byte(token), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "ca.crt"), ca, 0o600)

	svc, owner, srvURL, enroll := controlPlane(t)
	cfg := &agent.Config{Server: srvURL, StateDir: filepath.Join(dir, "state"), Name: "kind", Targets: []agent.TargetConfig{},
		Kubernetes: &agent.KubeConfig{Cluster: "kind", APIServer: server, TokenFile: filepath.Join(dir, "token"), CAFile: filepath.Join(dir, "ca.crt")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	a := enroll(cfg)
	if _, err := svc.RequestInventoryScan(ctx, owner, "kind"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PollOnce(ctx, 0); err != nil {
		t.Fatal(err)
	}

	inv, err := svc.AgentInventory(ctx, owner, "kind")
	if err != nil || inv["inventory"] == nil {
		t.Fatalf("no inventory stored: %v %v", inv, err)
	}
	var stored struct {
		Kubernetes agentproto.KubeInventory `json:"kubernetes"`
	}
	if err := json.Unmarshal(inv["inventory"].(json.RawMessage), &stored); err != nil {
		t.Fatal(err)
	}
	kinv := stored.Kubernetes
	if len(kinv.Errors) != 0 {
		t.Fatalf("listing errors with the manifest's RBAC: %v", kinv.Errors)
	}
	byName := map[string]agentproto.KubeCert{}
	for _, c := range kinv.Certificates {
		byName[c.Name] = c
	}
	if byName["good"].RequestName == "" || byName["good"].NotAfter == "" {
		t.Fatalf("good certificate: %+v", byName["good"])
	}
	notReady := false
	for _, c := range byName["bad"].Conditions {
		notReady = notReady || c.Type == "Ready" && c.Status == "False"
	}
	if !notReady {
		t.Fatalf("bad certificate should be not Ready: %+v", byName["bad"])
	}
	findings := map[string]string{}
	_ = svc.DB.WithOrg(ctx, owner.OrgID, func(tx *store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT check_id, subject_id FROM findings WHERE subject_type = 'k8s_object' AND resolved_at IS NULL`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c, s string
			_ = rows.Scan(&c, &s)
			findings[c] = s
		}
		var n int
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE source = 'kubernetes'`).Scan(&n)
		if n != 1 {
			t.Errorf("want the good certificate imported from its CertificateRequest, got %d", n)
		}
		return rows.Err()
	})
	if !strings.HasSuffix(findings["k8s_issuer_not_ready"], "/Issuer/web/broken") {
		t.Errorf("issuer finding: %v", findings)
	}
	if !strings.HasSuffix(findings["k8s_bundle_not_synced"], "/Bundle//trust") {
		t.Errorf("bundle finding: %v", findings)
	}
}

// controlPlane starts an in-process control plane with an agent listener
// and returns a function that enrolls an agent config against it.
func controlPlane(t *testing.T) (*app.Service, authz.Principal, string, func(*agent.Config) *agent.Agent) {
	db := storetest.New(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	kk, _ := kek.New(key)
	pki, err := agentpki.LoadOrCreate(ctx, db.Pool, kk)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &app.Service{DB: db.DB, Prober: probe.New(), Log: log, PKI: pki}
	as := &agentapi.Server{Svc: svc, Log: log}
	tcfg, err := as.TLSConfig([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(as.Handler())
	srv.TLS = tcfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	org, _ := db.CreateOrg(ctx, "kube")
	owner := authz.Principal{OrgID: org.ID, Actor: "user:owner", Role: store.RoleOwner}
	return svc, owner, srv.URL, func(cfg *agent.Config) *agent.Agent {
		tok, err := svc.CreateEnrollmentToken(ctx, owner, "", time.Hour, srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := agent.Enroll(ctx, cfg, tok.Token, tok.CAHash, "kind-node"); err != nil {
			t.Fatal(err)
		}
		a, err := agent.New(cfg, log)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		if err := a.Heartbeat(ctx); err != nil {
			t.Fatal(err)
		}
		return a
	}
}
