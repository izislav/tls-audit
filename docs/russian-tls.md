# Russian TLS / GOST Compatibility

This block is intentionally separate from the global TLS grade.

Global TLS security answers:

- Is the site safe and trusted in common international browsers?
- Does it use modern TLS protocols and cipher suites?
- Is the certificate chain valid for the public WebPKI?

Russian TLS compatibility answers:

- Does the certificate chain match a Russian trust list?
- Are GOST OIDs present in certificate signatures or public keys?
- Is there evidence of GOST TLS support?
- Is the Russian trust list fresh enough to rely on?

The Russian block must not automatically improve `A` or `A+`. A site can be
compatible with a Russian trust environment and still fail global browser trust,
or be globally strong and not provide GOST TLS. These are different conclusions.

Initial data lives in `data/russian_trust/roots.sample.json`. It is a placeholder,
not a production trust source. Production needs:

- official source URL;
- update command;
- SHA-256 fingerprints;
- update timestamp;
- stale-list warning when the data is old.

