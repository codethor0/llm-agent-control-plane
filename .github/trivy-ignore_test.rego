package trivy

pip_sbom_finding := {
	"VulnerabilityID": "CVE-2025-47273",
	"PkgIdentifier": {
		"PURL": "pkg:pypi/setuptools@70.3.0",
		"BOMRef": "pkg:pypi/setuptools@70.3.0",
	},
}

before_expiry := time.parse_rfc3339_ns("2027-05-18T23:59:59Z")

at_expiry := time.parse_rfc3339_ns("2027-05-19T00:00:00Z")

test_pathless_pip_sbom_finding_is_ignored_before_expiry {
	ignore with input as pip_sbom_finding with time.now_ns as before_expiry
}

test_installed_setuptools_remains_reportable {
	finding := object.union(pip_sbom_finding, {"PkgPath": "site-packages/setuptools-70.3.0.dist-info/METADATA"})
	not ignore with input as finding with time.now_ns as before_expiry
}

test_pathless_finding_without_sbom_reference_remains_reportable {
	finding := object.union(pip_sbom_finding, {"PkgIdentifier": {"PURL": "pkg:pypi/setuptools@70.3.0", "BOMRef": ""}})
	not ignore with input as finding with time.now_ns as before_expiry
}

test_pip_sbom_finding_is_reported_at_expiry {
	not ignore with input as pip_sbom_finding with time.now_ns as at_expiry
}
