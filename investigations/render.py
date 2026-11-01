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
/* Report: a long-form threat brief in the campaign-graph dark look. */
@font-face { font-family: "Geist"; src: url("/fonts/Geist-Variable.woff2") format("woff2"); font-weight: 100 900; font-display: swap; }
@font-face { font-family: "Geist Mono"; src: url("/fonts/GeistMono-Variable.woff2") format("woff2"); font-weight: 100 900; font-display: swap; }
:root {
  color-scheme: dark;
  --bg: #02090c; --paper: rgba(5, 16, 21, 0.78); --text: #f3f5f4; --text-2: rgba(243, 245, 244, 0.72); --muted: rgba(243, 245, 244, 0.48);
  --rule: rgba(243, 245, 244, 0.12); --code-bg: rgba(243, 245, 244, 0.07); --accent: #55d8d4;
  --high: #4bfaa9; --mod: #f2b84b; --low: #f26c53;
  --sans: "Geist", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Arial, sans-serif;
  --mono: "Geist Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body { margin: 0; color: var(--text); font: 16px/1.65 var(--sans); background:
  radial-gradient(1100px 520px at 85% -10%, rgba(85, 216, 212, 0.14), transparent 70%),
  radial-gradient(900px 480px at 0% 0%, rgba(46, 102, 158, 0.18), transparent 70%), var(--bg); background-repeat: no-repeat; }
article { max-width: 900px; margin: 0 auto; padding-block: 36px 80px;
  padding-left: max(20px, env(safe-area-inset-left, 0px)); padding-right: max(20px, env(safe-area-inset-right, 0px)); }
.topline { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 10px; margin-bottom: 34px; }
.home, .tlp { font: 400 11px/1.4 var(--mono); text-transform: uppercase; letter-spacing: .08em; color: var(--text-2); }
.home { color: var(--accent); text-decoration: none; }
.home:hover { text-decoration: underline; text-underline-offset: 3px; }
.tlp { border: 1px solid var(--rule); padding: 4px 10px; }
h1 { font-weight: 400; font-size: clamp(38px, 6.4vw, 76px); line-height: 0.98; letter-spacing: -0.055em; margin: 0 0 28px; text-wrap: balance; }
h2 { font: 400 11px/1.4 var(--mono); text-transform: uppercase; letter-spacing: .1em; color: var(--muted); margin: 52px 0 14px; padding-top: 16px; border-top: 1px solid var(--rule); }
p, li { max-width: 72ch; color: var(--text-2); }
p strong, li strong, td strong { color: var(--text); font-weight: 500; }
li { margin: 6px 0; }
ol > li::marker { font-family: var(--mono); color: var(--accent); }
a { color: var(--accent); text-decoration-color: rgba(85, 216, 212, 0.45); text-underline-offset: 3px; }
a:hover { text-decoration-color: var(--accent); }
em { color: var(--text-2); }
code { font: 0.84em var(--mono); background: var(--code-bg); color: var(--text); padding: 1px 6px; border-radius: 5px; overflow-wrap: anywhere; }
pre { background: var(--paper); border: 1px solid var(--rule); padding: 16px 18px; border-radius: 12px; overflow-x: auto; line-height: 1.55; }
pre code { background: none; padding: 0; font-size: 0.8rem; color: var(--text-2); overflow-wrap: normal; }
.table-wrap { overflow-x: auto; margin: 14px 0 20px; border: 1px solid var(--rule); border-radius: 12px; background: var(--paper); }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
th, td { text-align: left; vertical-align: top; padding: 9px 14px; border-bottom: 1px solid var(--rule); color: var(--text-2); }
tr:last-child td { border-bottom: 0; }
th { font: 400 10.5px/1.4 var(--mono); text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
td:first-child { white-space: nowrap; color: var(--text); }
.conf { font-weight: 500; font-style: normal; }
.conf.high { color: var(--high); } .conf.moderate { color: var(--mod); } .conf.low { color: var(--low); }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
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
    # --untagged: a plain docs page, not an investigation (no TLP marking, own title)
    untagged = "--untagged" in sys.argv
    page_title = f"campaign-graph {title}" if untagged else title.split(":")[0].strip() + " Investigation"
    head = f"<title>{page_title}</title>\n<style>{CSS}</style>\n"
    home = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--home=")), None)
    nav = f'<a class="home" href="{home}">&larr; campaign-graph explorer</a>' if home else "<span></span>"
    tlp = "" if untagged else '<span class="tlp">TLP:CLEAR · defanged · victim data removed</span>'
    article = f'<article><div class="topline">{nav}{tlp}</div>\n{body}</article>\n'
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
