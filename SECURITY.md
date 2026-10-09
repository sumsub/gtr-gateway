# Security policy

Please report a vulnerability in the libraries, the examples or the contract privately, never in a
public issue or pull request: through GitHub's private vulnerability reporting (**Security → Report
a vulnerability** on this repository), through the channels listed in Sumsub's
[security.txt](https://sumsub.com/.well-known/security.txt), or through your Sumsub account manager.
Include the affected component and version, what an attacker can achieve, and the steps to
reproduce.

Security fixes are released for the latest minor version of each library: `go/vX.Y.Z` for
`github.com/sumsub/gtr-gateway/go` and `typescript/vX.Y.Z` for `@sumsub/gtr-gateway`. The examples are
reference code that you build and operate yourself; Sumsub does not publish container images.

[docs/security.md](docs/security.md) explains how to deploy and operate the gateway securely.
