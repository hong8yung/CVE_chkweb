from __future__ import annotations

import re

IMPACT_CLASSIFICATION_VERSION = "v1"
IMPACT_TYPE_OPTIONS = [
    "Remote Code Execution",
    "Authentication Bypass",
    "Privilege Escalation",
    "SQL Injection",
    "Command Injection",
    "Code Injection",
    "Cross-Site Scripting",
    "Path Traversal",
    "Server-Side Request Forgery",
    "Insecure Deserialization",
    "Denial of Service",
    "Information Disclosure",
    "Memory Corruption",
    "Other",
]


def classify_impact_type(description: str) -> str:
    text = description.lower()
    if re.search(r"\brce\b", text):
        return "Remote Code Execution"

    rules = [
        ("remote code execution", "Remote Code Execution"),
        ("authentication bypass", "Authentication Bypass"),
        ("auth bypass", "Authentication Bypass"),
        ("privilege escalation", "Privilege Escalation"),
        ("sql injection", "SQL Injection"),
        ("command injection", "Command Injection"),
        ("code injection", "Code Injection"),
        ("cross-site scripting", "Cross-Site Scripting"),
        ("xss", "Cross-Site Scripting"),
        ("path traversal", "Path Traversal"),
        ("directory traversal", "Path Traversal"),
        ("ssrf", "Server-Side Request Forgery"),
        ("request forgery", "Server-Side Request Forgery"),
        ("deserialization", "Insecure Deserialization"),
        ("denial of service", "Denial of Service"),
        ("dos", "Denial of Service"),
        ("information disclosure", "Information Disclosure"),
        ("out-of-bounds", "Memory Corruption"),
        ("buffer overflow", "Memory Corruption"),
        ("use-after-free", "Memory Corruption"),
    ]
    for keyword, label in rules:
        if keyword in text:
            return label
    return "Other"
