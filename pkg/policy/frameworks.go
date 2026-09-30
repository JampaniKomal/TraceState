package policy

import "sort"

// Framework describes a compliance framework or control catalogue that rules
// can be mapped to. Control titles are used to make reports readable; a rule
// may still reference a control that isn't listed here.
type Framework struct {
	ID       string
	Name     string
	Controls map[string]string
}

// Catalog is the set of frameworks TraceState knows how to label.
var Catalog = map[string]Framework{
	"ISO27001": {
		ID:   "ISO27001",
		Name: "ISO/IEC 27001:2022 Annex A",
		Controls: map[string]string{
			"A.5.15": "Access control",
			"A.5.17": "Authentication information",
			"A.5.21": "Managing information security in the ICT supply chain",
			"A.5.34": "Privacy and protection of PII",
			"A.8.2":  "Privileged access rights",
			"A.8.5":  "Secure authentication",
			"A.8.8":  "Management of technical vulnerabilities",
			"A.8.9":  "Configuration management",
			"A.8.11": "Data masking",
			"A.8.12": "Data leakage prevention",
			"A.8.15": "Logging",
			"A.8.20": "Networks security",
			"A.8.21": "Security of network services",
			"A.8.22": "Segregation of networks",
			"A.8.24": "Use of cryptography",
			"A.8.26": "Application security requirements",
			"A.8.27": "Secure system architecture and engineering principles",
			"A.8.28": "Secure coding",
			"A.8.32": "Change management",
		},
	},
	"DPDPA": {
		ID:   "DPDPA",
		Name: "Digital Personal Data Protection Act, 2023 (India)",
		Controls: map[string]string{
			"s.8(4)": "Appropriate technical and organisational measures",
			"s.8(5)": "Reasonable security safeguards to prevent personal data breach",
		},
	},
	"HIPAA": {
		ID:   "HIPAA",
		Name: "HIPAA Security Rule (45 CFR 164.312)",
		Controls: map[string]string{
			"164.312(a)(1)":     "Access control",
			"164.312(a)(2)(iv)": "Encryption and decryption",
			"164.312(b)":        "Audit controls",
			"164.312(d)":        "Person or entity authentication",
			"164.312(e)(1)":     "Transmission security",
		},
	},
	"PCI-DSS": {
		ID:   "PCI-DSS",
		Name: "PCI DSS v4.0",
		Controls: map[string]string{
			"3.5.1": "PAN is rendered unreadable anywhere it is stored",
			"4.2.1": "Strong cryptography protects PAN during transmission",
			"8.3.2": "Strong cryptography renders authentication factors unreadable",
		},
	},
	"NIST-CSF": {
		ID:   "NIST-CSF",
		Name: "NIST Cybersecurity Framework 2.0",
		Controls: map[string]string{
			"ID.RA-01": "Vulnerabilities in assets are identified, validated, and recorded",
			"PR.AA-01": "Identities and credentials are managed",
			"PR.AA-05": "Access permissions follow least privilege",
			"PR.DS-01": "Data-at-rest is protected",
			"PR.DS-02": "Data-in-transit is protected",
			"PR.IR-01": "Networks are protected from unauthorized logical access",
			"PR.PS-01": "Configuration management practices are applied",
			"PR.PS-02": "Software is maintained commensurate with risk",
			"PR.PS-04": "Log records are generated for continuous monitoring",
		},
	},
	"SEBI-CSCRF": {
		ID:   "SEBI-CSCRF",
		Name: "SEBI Cybersecurity and Cyber Resilience Framework (2024)",
		Controls: map[string]string{
			"Protect/Data-Security":             "Protect: data security and cryptography",
			"Protect/Access-Control":            "Protect: identity and access management",
			"Identify/Vulnerability-Management": "Identify: vulnerability assessment and patching",
		},
	},
	"OWASP": {
		ID:   "OWASP",
		Name: "OWASP Top 10 (2021)",
		Controls: map[string]string{
			"A01": "Broken Access Control",
			"A02": "Cryptographic Failures",
			"A05": "Security Misconfiguration",
			"A06": "Vulnerable and Outdated Components",
			"A07": "Identification and Authentication Failures",
			"A08": "Software and Data Integrity Failures",
			"A09": "Security Logging and Monitoring Failures",
		},
	},
	"CWE": {
		ID:   "CWE",
		Name: "Common Weakness Enumeration",
		Controls: map[string]string{
			"CWE-250":  "Execution with Unnecessary Privileges",
			"CWE-256":  "Plaintext Storage of a Password",
			"CWE-295":  "Improper Certificate Validation",
			"CWE-306":  "Missing Authentication for Critical Function",
			"CWE-312":  "Cleartext Storage of Sensitive Information",
			"CWE-321":  "Use of Hard-coded Cryptographic Key",
			"CWE-326":  "Inadequate Encryption Strength",
			"CWE-359":  "Exposure of Private Personal Information",
			"CWE-532":  "Insertion of Sensitive Information into Log File",
			"CWE-668":  "Exposure of Resource to Wrong Sphere",
			"CWE-798":  "Use of Hard-coded Credentials",
			"CWE-829":  "Inclusion of Functionality from Untrusted Control Sphere",
			"CWE-942":  "Permissive Cross-domain Policy with Untrusted Domains",
			"CWE-1104": "Use of Unmaintained Third Party Components",
			"CWE-1395": "Dependency on Vulnerable Third-Party Component",
		},
	},
	"CIS-Docker": {
		ID:   "CIS-Docker",
		Name: "CIS Docker Benchmark (recommendation titles)",
		Controls: map[string]string{
			"non-root-user":        "Containers run as a non-root user",
			"no-privileged":        "Privileged containers are not used",
			"no-docker-socket":     "The Docker socket is not mounted inside containers",
			"no-host-namespaces":   "Host network, PID and IPC namespaces are not shared",
			"pinned-images":        "Images are pinned to an immutable version",
			"no-secrets-in-env":    "Secrets are not stored in container environment or image layers",
			"bind-host-interface":  "Published ports are bound to a specific host interface",
			"trusted-build-inputs": "Build inputs come from trusted, verified sources",
		},
	},
}

// ControlTitle returns the human-readable title for a control, or "" if the
// framework or control isn't in the catalogue.
func ControlTitle(framework, control string) string {
	if fw, ok := Catalog[framework]; ok {
		return fw.Controls[control]
	}
	return ""
}

// FrameworkName returns the display name for a framework ID, falling back to
// the ID itself.
func FrameworkName(id string) string {
	if fw, ok := Catalog[id]; ok {
		return fw.Name
	}
	return id
}

// ControlRef is one (framework, control) pair a rule maps to.
type ControlRef struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
	Title     string `json:"title,omitempty"`
}

// SortedControls flattens a framework->controls map into a stable list.
func SortedControls(m map[string][]string) []ControlRef {
	var refs []ControlRef
	for fw, controls := range m {
		for _, c := range controls {
			refs = append(refs, ControlRef{Framework: fw, Control: c, Title: ControlTitle(fw, c)})
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Framework != refs[j].Framework {
			return refs[i].Framework < refs[j].Framework
		}
		return ControlLess(refs[i].Control, refs[j].Control)
	})
	return refs
}

// ControlLess orders control IDs naturally, so "A.8.2" sorts before "A.8.11"
// and "CWE-79" before "CWE-200".
func ControlLess(a, b string) bool {
	ia, ib := 0, 0
	for ia < len(a) && ib < len(b) {
		ca, cb := a[ia], b[ib]
		if isDigit(ca) && isDigit(cb) {
			na, nb := 0, 0
			for ia < len(a) && isDigit(a[ia]) {
				na = na*10 + int(a[ia]-'0')
				ia++
			}
			for ib < len(b) && isDigit(b[ib]) {
				nb = nb*10 + int(b[ib]-'0')
				ib++
			}
			if na != nb {
				return na < nb
			}
			continue
		}
		if ca != cb {
			return ca < cb
		}
		ia++
		ib++
	}
	return len(a)-ia < len(b)-ib
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
