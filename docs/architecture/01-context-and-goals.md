# Context and goals

This document describes how *openstack-spiffe* works and why it is built the way it is, for architects, security reviewers and auditors. It is self-contained. The *Setup Guide* explains how to install it, and the *Operator's Guide* how to run it. The project's specifications, in its source repository, hold the full design detail for its developers.

## The problem

SPIFFE gives workloads cryptographic identities, and SPIRE issues them. Before SPIRE Server trusts a workload, it must trust the machine the workload runs on: its *node*. SPIRE establishes that trust by *node attestation*: the node's SPIRE Agent proves to SPIRE Server what the node is, with evidence SPIRE Server can verify independently.

Public clouds sign such evidence for their instances: AWS's instance identity documents, Azure's and GCP's identity tokens. OpenStack does not. Its metadata service tells an instance who it is, but nothing it serves is signed, and nothing a SPIRE Server could verify. The usual workarounds each give something up:

- **Join tokens**, created by an operator and handed to each instance: someone must deliver a secret to every instance, which does not scale and puts secrets in images or user data.
- **Trusting network position**, accepting any agent that can reach the metadata service: anything running on the network, inside an instance or not, can claim to be any instance.
- **Calling the Nova API from SPIRE Server** with the agent's claims: the claims come from the instance, which can lie, and SPIRE Server needs credentials that can read every instance of the cloud.

## The solution

*openstack-spiffe* lets OpenStack sign what it knows. A small service, the **issuer**, runs beside the control plane as a Nova *vendordata* target. Whenever an instance reads its metadata, Nova calls the issuer on the instance's behalf, authenticated. The issuer confirms the instance with the Nova API, and returns a short-lived token, signed with its own keys, stating the instance's project and ID. Nova hands the token to the instance in its metadata. SPIRE Agent's **agent plugin** presents it, and SPIRE Server's **server plugin** verifies it against the issuer's public keys.

The trust therefore rests on the OpenStack control plane, the only party that knows which instance is which, and on the issuer's keys, never on anything the instance says about itself.

## Goals

- **No secrets in instances or images.** An instance obtains its proof from OpenStack when it boots.
- **Cryptographic node identity.** SPIRE Server verifies a signature against keys it fetches over verified TLS. Nothing is accepted because of where it comes from.
- **Control-plane facts only, where it matters.** The project and instance IDs come from Nova and are confirmed against the Nova API. Values a tenant can set are marked as such.
- **Short-lived, single-use proofs.** A token is valid for 5 minutes and accepted once, so a stolen one is worth little.
- **No single point of failure.** The issuer runs as independent replicas, each with its own keys.
- **Accountability.** Every token issued and every attestation is recorded, and the records can be joined.
- **Standard operations.** Packages, systemd units, a configuration check, health probes and metrics, verifiable signed releases.

## Non-goals

- **Workload attestation**: that stays SPIRE Agent's job, with its usual workload attestors.
- **Registration entry automation**: entries are created as with any SPIRE deployment.
- **Protecting a node from its own root user**: root in an instance controls the instance, and its identity, by definition.
- **Securing OpenStack itself**: the solution relies on Nova, Neutron and Keystone behaving correctly (see *Threat model*).
