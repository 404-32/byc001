# Security policy

## Supported versions

Security fixes are applied to the latest published minor release. At the time of
writing this is the `0.3.x` series.

## Input model

`moon-pe-inspect` is intended to inspect untrusted PE files. The parser:

- checks every read against the available byte range;
- limits loops and recursion using explicit safety bounds;
- does not load or execute inspected binaries;
- does not follow network resources;
- reports malformed structures with a file offset and message.

The certificate-table parser only lists `WIN_CERTIFICATE` records. It does not
validate certificate chains or Authenticode signatures. A reported certificate
must not be interpreted as proof that a file is trusted.

## Reporting a vulnerability

Please do not open a public issue containing an exploitable sample or sensitive
data. Use the repository owner's private security-advisory channel on GitHub when
available, or contact the owner through the GitHub profile linked from the
repository. Include the affected version, a minimal reproducer when safe, and the
observed impact.
