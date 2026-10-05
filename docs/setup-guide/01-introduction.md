# Introduction

This guide installs and configures *openstack-spiffe*, which lets the instances of an OpenStack cloud obtain a SPIFFE identity from SPIRE without any secret baked into their images. It is written for the people who run the OpenStack control plane, the SPIRE Server and the instance images. The companion documents explain how the solution works and why it is safe (*Architecture and Design*), and how to run it day to day (*Operator's Guide*).

## What the solution does

SPIRE gives every workload a SPIFFE identity, but first it must trust the machine the workload runs on: its *node attestation*. On OpenStack, the only party that knows for certain which project an instance belongs to is OpenStack itself. *openstack-spiffe* makes that knowledge available to SPIRE:

1. When an instance reads its metadata, Nova calls the **issuer** (`openstack-spire-issuer`) on the instance's behalf. The issuer authenticates Nova, checks the instance against the Nova API, and returns a short-lived signed token (a JWT) stating the instance's project and ID.
2. Inside the instance, SPIRE Agent's **agent plugin** (`openstack-agent-plugin`) reads the token from the metadata service and presents it to SPIRE Server.
3. In SPIRE Server, the **server plugin** (`openstack-server-plugin`) verifies the token against the issuer's public keys, and gives the agent its SPIFFE ID and selectors, such as `openstack_iid:project_id:<id>`.

The instance never holds a long-lived credential: each token is valid for 5 minutes, accepted once, and only ever obtained through Nova.

## The components and where they run

| Component | Package | Runs on |
| ------------------------ | ---------------------------- | ------------------------------------------------ |
| Issuer: signer replicas | `openstack-spire-issuer` | Two or more hosts that the `nova-api-metadata` service can reach, typically beside the OpenStack control plane |
| Issuer: JWKS aggregator (optional) | `openstack-spire-issuer` | Hosts that SPIRE Server can reach, when SPIRE Server must not reach the signers |
| Server plugin | `openstack-server-plugin` | Every SPIRE Server |
| Agent plugin | `openstack-agent-plugin` | Every instance running SPIRE Agent, usually baked into the image |

![How an instance's SPIRE Agent gets its identity](attestation-overview.pdf){width=100%}

## How this guide is organized

The chapters follow the order of a first installation:

- *Prerequisites* and *Getting and verifying a release* prepare the hosts, names, certificates and packages.
- *OpenStack preparation* creates the users and configures Nova.
- *Installing the issuer*, *The JWKS aggregator*, *Installing the server plugin* and *Installing the agent plugin* install and configure each component.
- *Metrics* is optional.
- *End-to-end check* confirms that an instance attests, and *Upgrades and removal* covers what comes later.
- The *Configuration reference* describes every configuration key of the four configuration files: its purpose, default, choices, dependencies, caveats and security implications.

Commands are shown for a root shell (or with `sudo`) on Debian and Ubuntu (`apt`, `dpkg`) and RHEL-like systems (`dnf`, `rpm`). Paths are those the packages install.
