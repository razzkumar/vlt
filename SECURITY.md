# Security Policy

vlt takes security seriously. This policy describes how we handle security vulnerabilities and what is in scope for security reporting.

## Supported Versions

Only the latest release is actively supported with security fixes.

| Version | Status |
|---------|--------|
| Latest  | Supported |
| Older   | Not supported |

## Reporting a Vulnerability

If you discover a security vulnerability in vlt, please report it responsibly by emailing security@example.com instead of using the public issue tracker.

**Important:** Replace `security@example.com` with the actual security contact email when using this project.

In your report, include:

- Description of the vulnerability
- Steps to reproduce (if applicable)
- Affected version(s)
- Suggested fix (if available)

## Response Timeline

- **Acknowledgment:** Within 48 hours of your report
- **Assessment:** Initial security assessment within 3-5 business days
- **Critical fixes:** Released within 30 days (high-severity vulnerabilities)
- **Other fixes:** Included in the next regular release

After the patch is released, we will credit the reporter (unless you prefer anonymity).

## What Qualifies as a Vulnerability

The following categories are in scope for security reports:

### In Scope

- **Secret leakage:** Accidental exposure of sensitive data in logs, error messages, or output
- **Path traversal:** Ability to read/write files outside intended directories
- **Authentication bypass:** Unauthorized access to Vault secrets or operations
- **TLS/encryption issues:** Problems with HTTPS, certificate validation, or encryption implementation
- **Credential exposure:** Storage or transmission of credentials in plaintext when encryption is expected
- **Injection attacks:** Command injection, environment variable injection, or similar vulnerabilities
- **Privilege escalation:** Ability to perform operations beyond granted permissions

### Out of Scope

- **Denial of Service (DoS) against Vault itself** - These are Vault issues, not vlt issues
- **Social engineering** - Human factors outside the tool's scope
- **Theoretical vulnerabilities** - Without practical exploit path
- **Third-party library vulnerabilities** - Report to the library maintainers (we will update dependencies)
- **Feature requests** - File as GitHub issues, not security reports
- **Documentation typos** - File as GitHub issues

## Security Best Practices

When using vlt:

1. **Always verify TLS certificates** - Do not use `VAULT_SKIP_VERIFY=true` in production
2. **Rotate encryption keys regularly** - Follow your organization's key rotation policy
3. **Use short-lived tokens** - Implement token renewal for long-running processes
4. **Restrict file permissions** - .env files are created with mode 0600 (owner read/write only)
5. **Never commit secrets** - Add `.env` and `vlt.yaml` to `.gitignore`
6. **Audit Vault access** - Enable Vault audit logging to track secret access
7. **Limit Vault policies** - Grant only the minimum required permissions to users and AppRoles
8. **Monitor secret usage** - Track which secrets are accessed and when

## Security Updates

We will patch security vulnerabilities as follows:

- **High/Critical:** Released immediately in a patch release
- **Medium:** Included in the next scheduled release
- **Low:** Included in the next scheduled release, or deferred if no other changes are pending

All security updates will be announced in the GitHub releases page with a `[SECURITY]` tag.

## Vault Security

vlt relies on HashiCorp Vault for secret storage and encryption. For Vault security issues:

- Report to HashiCorp: https://www.hashicorp.com/security
- Never store the Vault unsealing key in vlt or in source control
- Keep your Vault instance updated

## Dependencies

vlt depends on several third-party libraries. If a vulnerability is found in a dependency:

1. We will update to a patched version as soon as available
2. A new release of vlt will be published
3. Users should update their vlt installation

Major dependencies:

- `github.com/hashicorp/vault/api` - Vault client library
- `github.com/urfave/cli/v2` - CLI framework
- `github.com/joho/godotenv` - .env file parsing
- `gopkg.in/yaml.v3` - YAML parsing

## Disclosure Policy

We follow responsible disclosure:

1. Reporters contact us privately
2. We acknowledge receipt and begin investigation
3. We develop and test a fix
4. We release the fix
5. We publicly disclose the vulnerability after the patch is available
6. We credit the reporter (unless anonymity is requested)

We will not publicly disclose vulnerability details until a fix is available and deployed.

## Questions?

For general security questions or clarification about this policy, please open a GitHub issue or contact the maintainers.
