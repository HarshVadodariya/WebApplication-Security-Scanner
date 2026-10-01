"""OWASP Top 10 mapping.

Findings carry a 2021-numbering key (A01, A02, A05, A07). The 2025 label is
shown alongside because the list was renumbered. The mapping is pragmatic
(by the kind of weakness), not an official CWE roll-up - edit it to match
your organisation's policy and verify labels against owasp.org/Top10.
"""

OWASP_TOP10 = {
    "A01": {
        "label_2021": "A01:2021 - Broken Access Control",
        "label_2025": "A01:2025 - Broken Access Control",
    },
    "A02": {
        "label_2021": "A02:2021 - Cryptographic Failures",
        "label_2025": "A04:2025 - Cryptographic Failures",
    },
    "A05": {
        "label_2021": "A05:2021 - Security Misconfiguration",
        "label_2025": "A02:2025 - Security Misconfiguration",
    },
    "A07": {
        "label_2021": "A07:2021 - Identification and Authentication Failures",
        "label_2025": "A07:2025 - Authentication Failures",
    },
}

SEVERITY_ORDER = ["High", "Medium", "Low", "Info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
