// Package osclient creates the service's authenticated OpenStack client. The
// service's own credentials come from the standard OS_* environment
// variables of an openrc file, never from the configuration file.
package osclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
)

// requestTimeout bounds every HTTP request to OpenStack; callers bound their
// own operations more tightly through the context.
const requestTimeout = 30 * time.Second

// Credentials are the service's OpenStack credentials and endpoint
// preferences, as read from the OS_* environment variables.
type Credentials struct {
	AuthURL string

	// password authentication
	UserID         string
	Username       string
	Password       string
	UserDomainID   string
	UserDomainName string

	// project scope (password authentication only)
	ProjectID         string
	ProjectName       string
	ProjectDomainID   string
	ProjectDomainName string

	// application credential authentication
	ApplicationCredentialID     string
	ApplicationCredentialName   string
	ApplicationCredentialSecret string

	// Region and Interface select catalog endpoints (Interface: public,
	// internal or admin).
	Region    string
	Interface string
}

// CredentialsFromEnv reads the credentials from the variables of a standard
// openrc file (OS_AUTH_URL, OS_USERNAME or OS_USER_ID, OS_PASSWORD,
// OS_USER_DOMAIN_NAME or _ID, OS_PROJECT_NAME or _ID, OS_PROJECT_DOMAIN_NAME
// or _ID; or OS_APPLICATION_CREDENTIAL_ID or _NAME and _SECRET; plus
// OS_REGION_NAME and OS_INTERFACE), through getenv (os.Getenv if nil).
// Unlike gophercloud's AuthOptionsFromEnv, it honours the user and project
// domain variables that openrc files set.
func CredentialsFromEnv(getenv func(string) string) (Credentials, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	c := Credentials{
		AuthURL:                     getenv("OS_AUTH_URL"),
		UserID:                      getenv("OS_USER_ID"),
		Username:                    getenv("OS_USERNAME"),
		Password:                    getenv("OS_PASSWORD"),
		UserDomainID:                getenv("OS_USER_DOMAIN_ID"),
		UserDomainName:              getenv("OS_USER_DOMAIN_NAME"),
		ProjectID:                   getenv("OS_PROJECT_ID"),
		ProjectName:                 getenv("OS_PROJECT_NAME"),
		ProjectDomainID:             getenv("OS_PROJECT_DOMAIN_ID"),
		ProjectDomainName:           getenv("OS_PROJECT_DOMAIN_NAME"),
		ApplicationCredentialID:     getenv("OS_APPLICATION_CREDENTIAL_ID"),
		ApplicationCredentialName:   getenv("OS_APPLICATION_CREDENTIAL_NAME"),
		ApplicationCredentialSecret: getenv("OS_APPLICATION_CREDENTIAL_SECRET"),
		Region:                      getenv("OS_REGION_NAME"),
		Interface:                   getenv("OS_INTERFACE"),
	}
	if err := c.validate(); err != nil {
		return Credentials{}, fmt.Errorf("reading OpenStack credentials from the environment: %w", err)
	}
	return c, nil
}

func (c *Credentials) validate() error {
	u, err := url.Parse(c.AuthURL)
	switch {
	case c.AuthURL == "":
		return errors.New("OS_AUTH_URL is not set")
	case err != nil || u.Host == "":
		return errors.New("OS_AUTH_URL is not a valid URL")
	case u.Scheme != "https":
		return errors.New("OS_AUTH_URL must use https: the service's credentials must not travel in clear")
	}

	c.Interface = strings.TrimSuffix(c.Interface, "URL") // accept the old publicURL form
	switch c.Interface {
	case "":
		c.Interface = "public"
	case "public", "internal", "admin":
	default:
		return fmt.Errorf("OS_INTERFACE %q must be public, internal or admin", c.Interface)
	}

	if c.ApplicationCredentialID != "" || c.ApplicationCredentialName != "" {
		switch {
		case c.ApplicationCredentialSecret == "":
			return errors.New("OS_APPLICATION_CREDENTIAL_SECRET is not set")
		case c.ApplicationCredentialID == "" && c.UserID == "" && (c.Username == "" || (c.UserDomainID == "" && c.UserDomainName == "")):
			return errors.New("an application credential given by name needs OS_USER_ID, or OS_USERNAME and OS_USER_DOMAIN_NAME (or _ID)")
		}
		// application credentials carry their own scope
		return nil
	}

	switch {
	case c.UserID == "" && c.Username == "":
		return errors.New("neither OS_USER_ID/OS_USERNAME nor OS_APPLICATION_CREDENTIAL_ID/_NAME is set")
	case c.UserID == "" && c.UserDomainID == "" && c.UserDomainName == "":
		return errors.New("OS_USERNAME needs OS_USER_DOMAIN_NAME or OS_USER_DOMAIN_ID")
	case c.Password == "":
		return errors.New("OS_PASSWORD is not set")
	case c.ProjectID == "" && c.ProjectName == "":
		return errors.New("OS_PROJECT_ID or OS_PROJECT_NAME must be set: an unscoped token carries no roles")
	case c.ProjectID == "" && c.ProjectDomainID == "" && c.ProjectDomainName == "":
		return errors.New("OS_PROJECT_NAME needs OS_PROJECT_DOMAIN_NAME or OS_PROJECT_DOMAIN_ID")
	}
	return nil
}

func (c Credentials) authOptions() gophercloud.AuthOptions {
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: c.AuthURL,
		// the service runs indefinitely: renew its token when it expires
		AllowReauth: true,
	}
	if c.ApplicationCredentialID != "" || c.ApplicationCredentialName != "" {
		opts.ApplicationCredentialID = c.ApplicationCredentialID
		opts.ApplicationCredentialName = c.ApplicationCredentialName
		opts.ApplicationCredentialSecret = c.ApplicationCredentialSecret
		opts.UserID, opts.Username = c.UserID, c.Username
		opts.DomainID, opts.DomainName = c.UserDomainID, c.UserDomainName
		return opts
	}
	opts.UserID, opts.Username, opts.Password = c.UserID, c.Username, c.Password
	opts.DomainID, opts.DomainName = c.UserDomainID, c.UserDomainName
	if c.ProjectID != "" {
		opts.Scope = &gophercloud.AuthScope{ProjectID: c.ProjectID}
	} else {
		opts.Scope = &gophercloud.AuthScope{ProjectName: c.ProjectName, DomainID: c.ProjectDomainID, DomainName: c.ProjectDomainName}
	}
	return opts
}

// Client is the service's authenticated OpenStack client.
type Client struct {
	provider  *gophercloud.ProviderClient
	endpoints gophercloud.EndpointOpts
}

// Option configures a Client.
type Option func(*options)

type options struct {
	minTLSVersion uint16
}

// WithMinTLSVersion sets the minimum TLS version of the connections to
// OpenStack (tls.VersionTLS12 or tls.VersionTLS13; default: TLS 1.3).
func WithMinTLSVersion(version uint16) Option {
	return func(o *options) { o.minTLSVersion = version }
}

// New authenticates with Keystone and returns the client. caCertPath is an
// optional PEM bundle that replaces the system roots for every OpenStack
// endpoint (keystone.ca_cert_path).
func New(ctx context.Context, creds Credentials, caCertPath string, opts ...Option) (*Client, error) {
	o := options{minTLSVersion: tls.VersionTLS13}
	for _, opt := range opts {
		opt(&o)
	}
	if o.minTLSVersion != tls.VersionTLS12 && o.minTLSVersion != tls.VersionTLS13 {
		return nil, fmt.Errorf("creating OpenStack client: unsupported minimum TLS version %#x", o.minTLSVersion)
	}
	tlsConfig := &tls.Config{MinVersion: o.minTLSVersion}
	if caCertPath != "" {
		pem, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("reading OpenStack CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("reading OpenStack CA bundle %s: no certificates found", caCertPath)
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	provider, err := openstack.NewClient(creds.AuthURL)
	if err != nil {
		return nil, fmt.Errorf("creating OpenStack client: %w", err)
	}
	provider.HTTPClient = http.Client{Transport: transport, Timeout: requestTimeout}
	provider.UserAgent.Prepend("openstack-spire-metadata")
	if err := openstack.Authenticate(ctx, provider, creds.authOptions()); err != nil {
		return nil, fmt.Errorf("authenticating with Keystone at %s: %w", creds.AuthURL, err)
	}
	return &Client{
		provider:  provider,
		endpoints: gophercloud.EndpointOpts{Region: creds.Region, Availability: gophercloud.Availability(creds.Interface)},
	}, nil
}

// ComputeMicroversion is the Nova API microversion the service requests:
// 2.47 embeds the flavor's original name in server records.
const ComputeMicroversion = "2.47"

// Compute returns a Nova client for the catalog's compute endpoint (selected
// by OS_REGION_NAME and OS_INTERFACE), using ComputeMicroversion.
func (c *Client) Compute() (*gophercloud.ServiceClient, error) {
	compute, err := openstack.NewComputeV2(c.provider, c.endpoints)
	if err != nil {
		return nil, fmt.Errorf("creating compute v2 client: %w", err)
	}
	compute.Microversion = ComputeMicroversion
	return compute, nil
}

// Identity returns a Keystone v3 client for the endpoint the service
// authenticated with (OS_AUTH_URL), not the catalog's.
func (c *Client) Identity() (*gophercloud.ServiceClient, error) {
	identity, err := openstack.NewIdentityV3(c.provider, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("creating identity v3 client: %w", err)
	}
	return identity, nil
}

// CheckIdentity checks that Keystone is reachable and accepts the service's
// token (GET /v3/auth/catalog). The request is authenticated, so an expired
// token is renewed rather than reported as a failure.
func (c *Client) CheckIdentity(ctx context.Context) error {
	identity, err := c.Identity()
	if err != nil {
		return err
	}
	if _, err := identity.Get(ctx, identity.ServiceURL("auth", "catalog"), nil, &gophercloud.RequestOpts{OkCodes: []int{http.StatusOK}}); err != nil {
		return fmt.Errorf("checking Keystone: %w", err)
	}
	return nil
}

// CheckCompute checks that the Nova API is reachable, by reading the compute
// endpoint's version document.
func (c *Client) CheckCompute(ctx context.Context) error {
	compute, err := c.Compute()
	if err != nil {
		return err
	}
	if _, err := compute.Get(ctx, compute.ResourceBaseURL(), nil, &gophercloud.RequestOpts{OkCodes: []int{http.StatusOK}}); err != nil {
		return fmt.Errorf("checking Nova: %w", err)
	}
	return nil
}
