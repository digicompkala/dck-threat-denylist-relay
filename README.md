# dck-threat-denylist-relay

High-confidence inbound HTTP threat denylist relay for DigiCompKala.

## Sources

- IPsum level 3: IPs appearing on at least 3 upstream blacklists.
- blocklist.de Apache: Apache / Apache-DDoS / RFI attackers from the last 48 hours.
- blocklist.de bruteforcelogin: WordPress/Joomla/web-login brute-force attackers.
- blocklist.de strongips: long-lived high-volume attackers.

## Safety policy

The generator validates every IP/CIDR, removes non-global/reserved networks, and excludes protected networks before publishing. Protected networks include:

- Official Google crawler/fetcher ranges from `digicompkala/dck-google-ipranges-relay`.
- DigiCompKala origin IP.
- Emalls whitelist.
- Torob whitelist.

If a required source fails or returns an unexpectedly small result, the workflow fails and the previous published denylist remains unchanged.

## Outputs

- `dist/dck-hard-deny-v4.txt`
- `dist/dck-hard-deny-v6.txt`
- `dist/dck-threat-report.json`

The workflow runs hourly. Generated outputs are committed only when content changes.

## Intended use

These files are intended to be consumed by server-side filtering such as ModSecurity or, after separate validation, Linux firewall/ipset/nftables rules. They are not a substitute for upstream volumetric DDoS protection.
