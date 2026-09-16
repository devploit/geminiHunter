# Security policy

## Reporting vulnerabilities

Report vulnerabilities in geminiHunter privately to [@devploit](https://github.com/devploit) using an available private contact channel on the profile. If GitHub private vulnerability reporting is enabled for this repository, use the **Security → Report a vulnerability** button. Do not post exploitable details or credentials in public issues.

Include the affected version, operating system, minimal reproduction using synthetic data, impact, and any proposed fix. Reports about keys found in another project should go to that project's owner or authorized disclosure program.

Security fixes target the latest version on the default branch; older snapshots are not maintained separately.

## Handling scan data

Run the tool only against targets and credentials you are authorized to assess. Validation and intelligence gathering send requests to Google's APIs, and the existing bypass and intelligence probes can generate content and consume quota. `--no-bypass` disables bypass attempts but does not disable validation or intelligence gathering.

JSON reports, detailed terminal output, evidence commands, and verbose logs can contain complete keys and target information. Treat them as credentials. Use `--key-file` or `-k -` to avoid placing keys directly in shell history and process arguments. Do not commit real targets, APKs, configuration containing credentials, or reports.

TLS certificate verification is enabled by default. `--insecure` disables verification and should only be used where the testing environment requires it.
