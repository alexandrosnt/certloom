package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// KubeConfig enables in-cluster observation of cert-manager and
// trust-manager (ADR-0023). The API server, token and CA default to the
// pod's service account.
type KubeConfig struct {
	Cluster   string `json:"cluster"`
	APIServer string `json:"api_server,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
	CAFile    string `json:"ca_file,omitempty"`
	// IntervalSeconds is how often the control plane should ask for an
	// inventory; default 300.
	IntervalSeconds int `json:"interval_seconds,omitempty"`
}

const (
	saDir          = "/var/run/secrets/kubernetes.io/serviceaccount"
	kubeListLimit  = 500
	kubeMaxObjects = 20000
)

func (c *Config) validateKube() []string {
	var p []string
	k := c.Kubernetes
	if k.Cluster == "" {
		p = append(p, "kubernetes.cluster is required (a name for this cluster)")
	}
	if len(c.Targets) > 0 {
		p = append(p, "kubernetes mode observes only; remove targets")
	}
	if k.APIServer != "" && !strings.HasPrefix(k.APIServer, "https://") {
		p = append(p, "kubernetes.api_server must be an https URL")
	}
	if k.IntervalSeconds != 0 && k.IntervalSeconds < 60 {
		p = append(p, "kubernetes.interval_seconds must be at least 60")
	}
	return p
}

type kubeClient struct {
	base      string
	tokenFile string
	hc        *http.Client
}

func newKubeClient(k *KubeConfig) (*kubeClient, error) {
	base := k.APIServer
	if base == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("not running in a cluster and kubernetes.api_server is not set")
		}
		base = "https://" + strings.Trim(host, "[]")
		if strings.Contains(host, ":") {
			base = "https://[" + host + "]"
		}
		base += ":" + port
	}
	caFile, tokenFile := k.CAFile, k.TokenFile
	if caFile == "" {
		caFile = saDir + "/ca.crt"
	}
	if tokenFile == "" {
		tokenFile = saDir + "/token"
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("%s has no certificates", caFile)
	}
	return &kubeClient{base: strings.TrimSuffix(base, "/"), tokenFile: tokenFile, hc: &http.Client{Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}, nil
}

// errKubeMissing marks a resource type the cluster does not serve (CRD not
// installed) or the agent may not read.
var errKubeMissing = errors.New("not available")

// list pages through a collection and decodes each item into T.
func kubeList[T any](ctx context.Context, c *kubeClient, path string) ([]T, error) {
	var out []T
	cont := ""
	for {
		q := url.Values{"limit": {strconv.Itoa(kubeListLimit)}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		if err := c.get(ctx, path+"?"+q.Encode(), &page); err != nil {
			return out, err
		}
		out = append(out, page.Items...)
		if page.Metadata.Continue == "" || len(out) >= kubeMaxObjects {
			return out, nil
		}
		cont = page.Metadata.Continue
	}
}

func (c *kubeClient) get(ctx context.Context, path string, v any) error {
	for attempt := 0; ; attempt++ {
		// Projected tokens rotate; read the file for every request.
		tok, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
		req.Header.Set("Accept", "application/json")
		resp, err := c.hc.Do(req)
		if err != nil {
			return err
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			err := json.NewDecoder(resp.Body).Decode(v)
			_ = resp.Body.Close()
			return err
		case resp.StatusCode == http.StatusTooManyRequests && attempt < 3:
			_ = resp.Body.Close()
			wait := time.Second
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && s <= 60 {
				wait = time.Duration(s) * time.Second
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden:
			_ = resp.Body.Close()
			return fmt.Errorf("%s: %w (HTTP %d)", path, errKubeMissing, resp.StatusCode)
		default:
			_ = resp.Body.Close()
			return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
		}
	}
}

type kubeMeta struct {
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations"`
}

type kubeCond struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	LastTransitionTime string `json:"lastTransitionTime"`
}

func convConds(in []kubeCond) []agentproto.KubeCondition {
	out := make([]agentproto.KubeCondition, 0, len(in))
	for _, c := range in {
		msg := c.Message
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		out = append(out, agentproto.KubeCondition{Type: c.Type, Status: c.Status, Reason: c.Reason, Message: msg, LastTransitionTime: c.LastTransitionTime})
	}
	return out
}

type kubeCertificate struct {
	Metadata kubeMeta `json:"metadata"`
	Spec     struct {
		SecretName string   `json:"secretName"`
		DNSNames   []string `json:"dnsNames"`
		IssuerRef  struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"issuerRef"`
	} `json:"spec"`
	Status struct {
		Revision    int        `json:"revision"`
		NotAfter    string     `json:"notAfter"`
		RenewalTime string     `json:"renewalTime"`
		Conditions  []kubeCond `json:"conditions"`
	} `json:"status"`
}

type kubeCertRequest struct {
	Metadata kubeMeta `json:"metadata"`
	Status   struct {
		Certificate []byte     `json:"certificate"` // base64 PEM in JSON
		Conditions  []kubeCond `json:"conditions"`
	} `json:"status"`
}

// requestFailure explains a CertificateRequest that will not be issued:
// Denied or InvalidRequest set, or Ready=False with reason Failed or Denied.
func requestFailure(conds []kubeCond) string {
	for _, c := range conds {
		terminal := (c.Type == "Denied" || c.Type == "InvalidRequest") && c.Status == "True" ||
			c.Type == "Ready" && c.Status == "False" && (c.Reason == "Failed" || c.Reason == "Denied")
		if terminal {
			return strings.TrimSpace(c.Type + ": " + c.Reason + " " + c.Message)
		}
	}
	return ""
}

type kubeIssuer struct {
	Metadata kubeMeta                   `json:"metadata"`
	Spec     map[string]json.RawMessage `json:"spec"`
	Status   struct {
		Conditions []kubeCond `json:"conditions"`
	} `json:"status"`
}

func issuerType(spec map[string]json.RawMessage) string {
	keys := make([]string, 0, len(spec))
	for k := range spec {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0] // an issuer spec has exactly one type key (acme, ca, selfSigned, vault, venafi)
}

type kubeBundle struct {
	Metadata kubeMeta `json:"metadata"`
	Spec     struct {
		Target map[string]json.RawMessage `json:"target"`
	} `json:"spec"`
	Status struct {
		Conditions []kubeCond `json:"conditions"`
	} `json:"status"`
}

type kubeIngress struct {
	Metadata kubeMeta `json:"metadata"`
	Spec     struct {
		TLS []struct {
			Hosts      []string `json:"hosts"`
			SecretName string   `json:"secretName"`
		} `json:"tls"`
	} `json:"spec"`
}

// inventoryKube lists cert-manager, trust-manager and Ingress objects with
// get/list only. Certificates come from CertificateRequest status, so no
// Secret is ever read.
func (a *Agent) inventoryKube(ctx context.Context) (*agentproto.KubeInventory, error) {
	c, err := newKubeClient(a.cfg.Kubernetes)
	if err != nil {
		return nil, err
	}
	inv := &agentproto.KubeInventory{Cluster: a.cfg.Kubernetes.Cluster, Certificates: []agentproto.KubeCert{},
		Issuers: []agentproto.KubeIssuer{}, Bundles: []agentproto.KubeBundle{}, Ingresses: []agentproto.KubeIngressTLS{}}
	soft := func(what string, err error) error {
		if errors.Is(err, errKubeMissing) {
			inv.Errors = append(inv.Errors, what+": "+err.Error())
			return nil
		}
		return err
	}
	certs, err := kubeList[kubeCertificate](ctx, c, "/apis/cert-manager.io/v1/certificates")
	if err := soft("certificates", err); err != nil {
		return nil, err
	}
	reqs, err := kubeList[kubeCertRequest](ctx, c, "/apis/cert-manager.io/v1/certificaterequests")
	if err := soft("certificaterequests", err); err != nil {
		return nil, err
	}
	byRev := map[string]*kubeCertRequest{}
	for i := range reqs {
		r := &reqs[i]
		ann := r.Metadata.Annotations
		byRev[r.Metadata.Namespace+"/"+ann["cert-manager.io/certificate-name"]+"#"+ann["cert-manager.io/certificate-revision"]] = r
	}
	for _, ct := range certs {
		kc := agentproto.KubeCert{Namespace: ct.Metadata.Namespace, Name: ct.Metadata.Name, SecretName: ct.Spec.SecretName,
			DNSNames: ct.Spec.DNSNames, IssuerKind: ct.Spec.IssuerRef.Kind, IssuerName: ct.Spec.IssuerRef.Name,
			Revision: ct.Status.Revision, NotAfter: ct.Status.NotAfter, RenewalTime: ct.Status.RenewalTime,
			Conditions: convConds(ct.Status.Conditions)}
		if kc.IssuerKind == "" {
			kc.IssuerKind = "Issuer"
		}
		if ct.Status.Revision > 0 {
			if r := byRev[ct.Metadata.Namespace+"/"+ct.Metadata.Name+"#"+strconv.Itoa(ct.Status.Revision)]; r != nil {
				kc.RequestName, kc.ChainPEM = r.Metadata.Name, string(r.Status.Certificate)
			}
		}
		// A request for the next revision that was denied or failed explains
		// why the certificate is not being renewed.
		if r := byRev[ct.Metadata.Namespace+"/"+ct.Metadata.Name+"#"+strconv.Itoa(ct.Status.Revision+1)]; r != nil {
			if why := requestFailure(r.Status.Conditions); why != "" {
				kc.RequestName, kc.RequestFailed = r.Metadata.Name, why
			}
		}
		inv.Certificates = append(inv.Certificates, kc)
	}
	issuers, err := kubeList[kubeIssuer](ctx, c, "/apis/cert-manager.io/v1/issuers")
	if err := soft("issuers", err); err != nil {
		return nil, err
	}
	cissuers, err := kubeList[kubeIssuer](ctx, c, "/apis/cert-manager.io/v1/clusterissuers")
	if err := soft("clusterissuers", err); err != nil {
		return nil, err
	}
	for _, is := range append(issuers, cissuers...) {
		inv.Issuers = append(inv.Issuers, agentproto.KubeIssuer{Namespace: is.Metadata.Namespace, Name: is.Metadata.Name,
			Type: issuerType(is.Spec), Conditions: convConds(is.Status.Conditions)})
	}
	bundles, err := kubeList[kubeBundle](ctx, c, "/apis/trust.cert-manager.io/v1alpha1/bundles")
	if err := soft("bundles", err); err != nil {
		return nil, err
	}
	for _, b := range bundles {
		var targets []string
		for k := range b.Spec.Target {
			targets = append(targets, k)
		}
		slices.Sort(targets)
		inv.Bundles = append(inv.Bundles, agentproto.KubeBundle{Name: b.Metadata.Name, Target: strings.Join(targets, ","),
			Conditions: convConds(b.Status.Conditions)})
	}
	ings, err := kubeList[kubeIngress](ctx, c, "/apis/networking.k8s.io/v1/ingresses")
	if err := soft("ingresses", err); err != nil {
		return nil, err
	}
	for _, ing := range ings {
		for _, t := range ing.Spec.TLS {
			inv.Ingresses = append(inv.Ingresses, agentproto.KubeIngressTLS{Namespace: ing.Metadata.Namespace, Name: ing.Metadata.Name,
				SecretName: t.SecretName, Hosts: t.Hosts})
		}
	}
	return inv, nil
}
