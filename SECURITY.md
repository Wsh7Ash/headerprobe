# Security Policy

## Supported versions

The latest release on `main` is supported; there are no versioned release
lines yet.

## Reporting a vulnerability

If you find a vulnerability or unsafe default in `headerprobe` itself, please open a
private security advisory on the GitHub repository (or open an issue describing the
problem at a high level if you cannot use advisories). We will acknowledge within
72 hours and coordinate a fix before public disclosure.

## Intended use

Probes only the URL you name. No crawling, no scanning of hosts you did not pass, no payload injection. Response headers may contain session cookies — treat --json-out as sensitive.

## Secrets

`headerprobe` stores no credentials and requires none. Do not commit real tokens, cookies
or keys to the spec/example files in this repository; `.gitignore` excludes `.env`
and common key material.
