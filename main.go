package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	apiv1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&hosteurDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type hosteurDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type hosteurDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
	APIEndpoint     string                  `json:"apiEndpoint"`
	APIKeySecretRef apiv1.SecretKeySelector `json:"apiKeySecretRef"`
	FK_CLIENT       string                  `json:"clientID"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *hosteurDNSProviderSolver) Name() string {
	return "hosteur-dns-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *hosteurDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		println(err.Error())
		return err
	}

	APIKeySecret, err := c.client.CoreV1().Secrets(ch.ResourceNamespace).Get(context.TODO(), cfg.APIKeySecretRef.Name, v1.GetOptions{})
	if err != nil {
		println(err.Error())
		return err
	}

	K_KEYBytes, ok := APIKeySecret.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		println("no secret")
		return nil
	}

	K_KEY := string(K_KEYBytes)

	hstApiClient := NewHstApiClient(cfg.FK_CLIENT, K_KEY, cfg.APIEndpoint)

	//code that sets a record in the DNS provider's console

	recordID := hstApiClient.findZone(ch.ResolvedZone, strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), "TXT")
	if recordID == "notFound" {
		hstApiClient.addRecord(ch.ResolvedZone, strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), ch.Key, "TXT", "3600", "0")
	} else {
		hstApiClient.updateRecord(ch.ResolvedZone, recordID, ch.Key, "TXT", "3600", "0")
	}
	
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *hosteurDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// TODO: add code that deletes a record from the DNS provider's console
	println("CleanUp")
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		println(err.Error())
		return err
	}

	APIKeySecret, err := c.client.CoreV1().Secrets(ch.ResourceNamespace).Get(context.TODO(), cfg.APIKeySecretRef.Name, v1.GetOptions{})
	if err != nil {
		println(err.Error())
		return err
	}

	K_KEYBytes, ok := APIKeySecret.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		println("no secret")
		return nil
	}

	K_KEY := string(K_KEYBytes)

	hstApiClient := NewHstApiClient(cfg.FK_CLIENT, K_KEY, cfg.APIEndpoint)

	// TODO: add code that sets a record in the DNS provider's console

	recordID := hstApiClient.findZone(ch.ResolvedZone, strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), "TXT")
	if recordID == "notFound" {
		return nil
	}
	hstApiClient.deleteRecord(ch.ResolvedZone, recordID)

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *hosteurDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		println(err.Error())
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (hosteurDNSProviderConfig, error) {
	cfg := hosteurDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
