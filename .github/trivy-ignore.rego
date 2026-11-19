package trivy

# pip 26.3's vendored SBOM lists setuptools 70.3.0, but the image has no
# setuptools/package_index.py. Trivy reports that SBOM entry without a package
# path. Keep the finding when Trivy identifies an installed package.
ignore {
	input.VulnerabilityID == "CVE-2025-47273"
	input.PkgIdentifier.PURL == "pkg:pypi/setuptools@70.3.0"
	input.PkgIdentifier.BOMRef == input.PkgIdentifier.PURL
	object.get(input, "PkgPath", "") == ""
	time.now_ns() < time.parse_rfc3339_ns("2027-05-19T00:00:00Z")
}
