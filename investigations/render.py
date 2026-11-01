"""Render an investigation README.md to a standalone page.

    python3 investigations/render.py investigations/CG-0001/README.md

Writes report.html next to the README. --fragment drops the document wrapper
(doctype/html/head/body) for hosts that add their own.
"""
import re
import sys
from pathlib import Path

import markdown

CSS = """
:root {
  color-scheme: light;
  --bg: #f6f6f3; --paper: #fdfdfb; --text: #151513; --text-2: #4f4e49; --muted: #7d7c75;
  --rule: #dddcd5; --code-bg: #efeee9; --accent: #1f5fae; --high: #0d7a3e; --mod: #a15c00; --low: #a83232;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --bg: #121211; --paper: #1a1a18; --text: #eeede8; --text-2: #c2c1b8; --muted: #8e8d85;
    --rule: #34342f; --code-bg: #24241f; --accent: #6aa6ef; --high: #4cc27c; --mod: #e0a04a; --low: #ec7b7b;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #121211; --paper: #1a1a18; --text: #eeede8; --text-2: #c2c1b8; --muted: #8e8d85;
  --rule: #34342f; --code-bg: #24241f; --accent: #6aa6ef; --high: #4cc27c; --mod: #e0a04a; --low: #ec7b7b;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 16px/1.6 var(--sans); }
article { max-width: 860px; margin: 0 auto; background: var(--paper); min-height: 100vh;
  padding-block: 40px 64px; padding-left: max(16px, env(safe-area-inset-left, 0px));
  padding-right: max(16px, env(safe-area-inset-right, 0px)); }
@media (min-width: 720px) { article { padding-left: 56px; padding-right: 56px; border-left: 1px solid var(--rule); border-right: 1px solid var(--rule); } }
h1 { font-size: 1.85rem; line-height: 1.2; letter-spacing: -0.015em; margin: 0 0 20px; text-wrap: balance; }
h2 { font-size: 1.2rem; margin: 40px 0 10px; padding-top: 16px; border-top: 1px solid var(--rule); text-wrap: balance; }
p, li { max-width: 72ch; }
li { margin: 4px 0; }
a { color: var(--accent); text-underline-offset: 2px; }
strong { font-weight: 650; }
em { color: var(--text-2); }
code { font: 0.86em var(--mono); background: var(--code-bg); padding: 1px 5px; border-radius: 4px; overflow-wrap: anywhere; }
pre { background: var(--code-bg); padding: 14px 16px; border-radius: 8px; overflow-x: auto; line-height: 1.5; }
pre code { background: none; padding: 0; font-size: 0.82rem; overflow-wrap: normal; }
.table-wrap { overflow-x: auto; margin: 12px 0 18px; }
table { border-collapse: collapse; width: 100%; font-size: 0.92rem; }
th, td { text-align: left; vertical-align: top; padding: 7px 10px; border-bottom: 1px solid var(--rule); }
th { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); font-weight: 600; }
td:first-child { white-space: nowrap; }
.conf { font-weight: 650; }
.conf.high { color: var(--high); } .conf.moderate { color: var(--mod); } .conf.low { color: var(--low); }
.tlp { display: inline-block; font: 600 0.75rem var(--mono); letter-spacing: .06em; border: 1px solid var(--rule); color: var(--text-2); padding: 2px 8px; border-radius: 4px; margin-bottom: 14px; }
"""


def render(md_text: str) -> tuple[str, str]:
    html = markdown.markdown(md_text, extensions=["tables", "fenced_code"])
    html = re.sub(r"<table>(.*?)</table>", r'<div class="table-wrap"><table>\1</table></div>', html, flags=re.S)
    # confidence words get a colour, but always keep the word itself
    html = re.sub(r"<(em|strong)>(?:\*)?(High|Moderate|Low) confidence(\.)?</\1>",
                  lambda m: f'<em class="conf {m[2].lower()}">{m[2]} confidence{m[3] or ""}</em>', html)
    html = re.sub(r"<strong>(High|Moderate|Low)</strong>",
                  lambda m: f'<strong class="conf {m[1].lower()}">{m[1]}</strong>', html)
    title = re.search(r"^# (.+)$", md_text, re.M)[1]
    return title, html


def main() -> None:
    src = Path(sys.argv[1])
    fragment = "--fragment" in sys.argv
    title, body = render(src.read_text())
    page_title = title.split(":")[0].strip() + " Investigation"
    head = f"<title>{page_title}</title>\n<style>{CSS}</style>\n"
    article = ('<article><span class="tlp">TLP:CLEAR · defanged · victim data removed</span>\n'
               f"{body}</article>\n")
    if fragment:
        out = head + article
    else:
        out = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
               '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
               f"{head}</head>\n<body>\n{article}</body>\n</html>\n")
    dest = Path(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else src.with_name("report.html")
    dest.write_text(out)
    print(f"wrote {dest}")


if __name__ == "__main__":
    main()
