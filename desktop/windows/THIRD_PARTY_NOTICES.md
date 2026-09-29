# Cerberus Windows third-party notices

The Windows bundle contains the same scanner engines used by the Docker edition.
Each component remains under its own license:

- Python 3.12 — Python Software Foundation License
- Node.js 22 — MIT and bundled third-party licenses
- Eclipse Temurin JRE 17 — GPLv2 with Classpath Exception and bundled notices
- Lighthouse 13.5.0 — Apache-2.0
- Nuclei — MIT
- Nuclei templates — MIT; individual templates may identify additional metadata
- sqlmap — GPL-2.0
- OWASP ZAP 2.17.0 — Apache-2.0 and bundled third-party notices
- OpenAI Codex CLI 0.152.0 — Apache-2.0
- Microsoft WebView2 SDK/runtime — Microsoft license terms

The build copies the license files distributed with these components into the
installer's `licenses` directory. Cerberus source is available at
<https://github.com/vaxman14/cerberus-selfhost> under AGPL-3.0-only.
