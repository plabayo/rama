# Specifications

## Automatic Certificate Management Environment (ACME)

A non-exhaustive collection of specifications as implemented,
relied upon by rama-tls-acme or related to.

### RFCs

* [rfc8555.txt](./rfc8555.txt)  
  Defines ACME, a protocol for automating domain validation, certificate issuance, and lifecycle management using X.509 PKI.

* [rfc8737.txt](./rfc8737.txt)  
  Defines the TLS-ALPN challenge method for ACME.

* [rfc8738.txt](./rfc8738.txt)  
  Defines IP identifier validation for ACME.

* [rfc8739.txt](./rfc8739.txt)  
  Defines support for short-term automatically renewed (STAR) certificates using ACME.

  This document proposes an Automated
  Certificate Management Environment (ACME) extension to enable the
  issuance of Short-Term, Automatically Renewed (STAR) X.509
  certificates.

* [rfc9773.txt](./rfc9773.txt)  
  ACME Renewal Information (ARI) Extension

  This document specifies how an Automated Certificate Management
  Environment (ACME) server may provide suggestions to ACME clients as
  to when they should attempt to renew their certificates.  This allows
  servers to mitigate load spikes and ensures that clients do not make
  false assumptions about appropriate certificate renewal periods.

* [rfc9444.txt](./rfc9444.txt)  
  Automated Certificate Management Environment (ACME) for Subdomains.

  This document specifies how a client can fulfill a
  challenge against an ancestor domain but may not need to fulfill a
  challenge against the explicit subdomain if certification authority
  policy allows issuance of the subdomain certificate without explicit
  subdomain ownership proof.

### Drafts

* [draft-ietf-acme-device-attest-02.txt](./draft-ietf-acme-device-attest-02.txt)  
  Defines device attestation support for ACME, introducing new identifiers and a challenge type to validate device identity.

  Supported already vendors such as Apple,
  see for more info on the latter at: <https://support.apple.com/en-vn/guide/deployment/dep28afbde6a/web>.
