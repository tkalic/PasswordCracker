"""
report.py — Audit report generator.

Produces an HTML report summarizing a cracking session:
- Attack parameters and result
- Hash algorithm security assessment
- Compliance evaluation (NIST SP 800-63B, ISO 27001 Annex A 8.24, BSI TR-02102-1)
- Recommendations
"""

import time
from pathlib import Path
from cracker.algorithms import HashAlgorithm, get_metadata, ALGORITHM_METADATA
from cracker.attacks import AttackResult


def _severity_color(secure: bool) -> str:
    return "#22c55e" if secure else "#ef4444"


def _compliance_badge(secure: bool) -> str:
    if secure:
        return '<span class="badge badge-pass">COMPLIANT</span>'
    return '<span class="badge badge-fail">NON-COMPLIANT</span>'


def generate_html_report(result: AttackResult, output_path: Path) -> Path:
    """
    Generate an HTML audit report from an AttackResult.

    Args:
        result:      AttackResult dataclass from an attack run.
        output_path: Where to write the .html file.

    Returns:
        Path to the written report.
    """
    meta = get_metadata(result.algorithm)
    secure = meta.get("secure", False)
    deprecated = meta.get("deprecated", False)
    standard = meta.get("standard", "N/A")
    crack_difficulty = meta.get("crack_difficulty", "N/A")
    iso_note = meta.get("iso27001", "N/A")

    status_text = "PASSWORD FOUND" if result.success else "NOT FOUND"
    status_color = "#ef4444" if result.success else "#22c55e"

    password_row = ""
    if result.success:
        password_row = f"""
        <tr>
            <td>Recovered Password</td>
            <td><code class="highlight">{result.password}</code></td>
        </tr>"""

    wordlist_row = ""
    if result.wordlist_path:
        wordlist_row = f"<tr><td>Wordlist</td><td>{result.wordlist_path}</td></tr>"

    charset_row = ""
    if result.charset:
        charset_row = f"<tr><td>Charset</td><td>{result.charset}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Password Security Audit Report</title>
<style>
  :root {{
    --bg: #0f1117;
    --surface: #1a1d27;
    --border: #2a2d3a;
    --text: #e2e8f0;
    --muted: #64748b;
    --accent: #3b82f6;
    --red: #ef4444;
    --green: #22c55e;
    --yellow: #f59e0b;
    --mono: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 15px;
    line-height: 1.6;
    padding: 2rem;
  }}
  .container {{ max-width: 860px; margin: 0 auto; }}
  header {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }}
  header h1 {{
    font-size: 1.5rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    color: var(--accent);
  }}
  header p {{ color: var(--muted); font-size: 0.875rem; margin-top: 0.25rem; }}
  .section {{ margin-bottom: 2rem; }}
  .section h2 {{
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.75rem;
  }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  td:first-child {{ color: var(--muted); width: 40%; font-size: 0.875rem; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{
    font-family: var(--mono);
    font-size: 0.85rem;
    background: rgba(255,255,255,0.06);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    word-break: break-all;
  }}
  code.highlight {{
    background: rgba(239,68,68,0.15);
    color: var(--red);
    font-weight: bold;
  }}
  .status-banner {{
    padding: 1rem 1.25rem;
    border-radius: 8px;
    font-weight: 600;
    font-size: 1rem;
    letter-spacing: 0.04em;
    border: 1px solid;
    margin-bottom: 2rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }}
  .badge {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }}
  .badge-fail {{ background: rgba(239,68,68,0.15); color: var(--red); }}
  .badge-pass {{ background: rgba(34,197,94,0.15); color: var(--green); }}
  .badge-warn {{ background: rgba(245,158,11,0.15); color: var(--yellow); }}
  .rec-list {{ list-style: none; padding: 0; }}
  .rec-list li {{
    padding: 0.6rem 1rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
    display: flex;
    gap: 0.6rem;
  }}
  .rec-list li:last-child {{ border-bottom: none; }}
  .rec-list li::before {{ content: "→"; color: var(--accent); }}
  footer {{
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.8rem;
  }}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>Password Security Audit Report</h1>
  <p>Generated: {result.timestamp} &nbsp;·&nbsp; Tool: PasswordCracker by Edwin Tkalic &nbsp;·&nbsp; github.com/tkalic</p>
</header>

<div class="status-banner" style="color:{status_color}; border-color:{status_color}; background:{'rgba(239,68,68,0.08)' if result.success else 'rgba(34,197,94,0.08)'}">
  <span>{'⚠' if result.success else '✓'}</span>
  <span>{status_text}</span>
</div>

<div class="section">
  <h2>Attack Summary</h2>
  <div class="card">
    <table>
      <tr><td>Attack Type</td><td>{result.attack_type.replace("_", " ").title()}</td></tr>
      <tr><td>Algorithm Targeted</td><td>{result.algorithm.value.upper()}</td></tr>
      <tr><td>Total Attempts</td><td>{result.attempts:,}</td></tr>
      <tr><td>Duration</td><td>{result.duration_seconds}s</td></tr>
      <tr><td>Speed</td><td>{result.hashes_per_second:,.0f} hashes/sec</td></tr>
      {wordlist_row}
      {charset_row}
      {password_row}
    </table>
  </div>
</div>

<div class="section">
  <h2>Algorithm Security Assessment</h2>
  <div class="card">
    <table>
      <tr><td>Algorithm</td><td>{result.algorithm.value.upper()} &nbsp; {_compliance_badge(secure)}</td></tr>
      <tr><td>Deprecated</td><td>{'Yes' if deprecated else 'No'}</td></tr>
      <tr><td>Standard Reference</td><td>{standard}</td></tr>
      <tr><td>Crack Difficulty</td><td>{crack_difficulty}</td></tr>
      <tr><td>ISO 27001 Note</td><td>{iso_note}</td></tr>
    </table>
  </div>
</div>

<div class="section">
  <h2>Recommendations</h2>
  <div class="card">
    <ul class="rec-list">
      {'<li>Migrate immediately to bcrypt (cost ≥ 12) or Argon2id for all password storage.</li>' if not secure else '<li>Algorithm is compliant. Ensure cost factor remains adequate as hardware improves.</li>'}
      {'<li>Audit all systems for use of MD5 or SHA1 in password storage.</li>' if deprecated else ''}
      <li>Enforce minimum password length of 12 characters per NIST SP 800-63B.</li>
      <li>Implement rate limiting and account lockout to slow online attacks.</li>
      <li>Use a secrets manager — never store plaintext passwords in config files or environment variables.</li>
      <li>Reference: NIST SP 800-63B · ISO/IEC 27001:2022 Annex A 8.24 · BSI TR-02102-1</li>
    </ul>
  </div>
</div>

<footer>
  This report was generated for educational and security assessment purposes only.
  Do not use this tool on systems you do not own or have explicit written permission to test.
  &nbsp;·&nbsp; PasswordCracker by Edwin Tkalic
</footer>

</div>
</body>
</html>"""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path
