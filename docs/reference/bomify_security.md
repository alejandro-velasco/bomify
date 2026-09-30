## bomify security

Security scanning commands

### Options

```
  -h, --help   help for security
```

### Options inherited from parent commands

```
      --data-dir string   directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable
      --docs-dir string   directory to write documentation to (if empty, no docs are generated)
      --verbose           enable verbose (debug) logging
```

### SEE ALSO

* [bomify](bomify.md)	 - bomify builds packages from CycloneDX SBOMs
* [bomify security policy](bomify_security_policy.md)	 - Manage vulnerability scanning policy rules
* [bomify security prune](bomify_security_prune.md)	 - Delete stale vulnerability report referrers of a package in a registry
* [bomify security scan](bomify_security_scan.md)	 - Scan a built package's components for vulnerabilities via a security scanning plugin
* [bomify security vex](bomify_security_vex.md)	 - Manage the VEX documents scan policy rules refer to

