"""HTML report generation from NDJSON audit logs.

Two reports are generated from each audit log:

- audit trace  (report.html)   — what the tool did: every LLM request/response
  and tool call, segmented by plan step, collapsible for debugging.

- findings     (findings.html) — pure security output: the reporter node's
  structured markdown rendered as a clean, printable security document.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

_MAX_LEN = 8000  # chars to show per output before truncating in HTML


# =============================================================================
# Public API
# =============================================================================

def generate_report(log_path: Path, report_path: Path) -> None:
    """Read *log_path* (NDJSON) and write the audit trace HTML to *report_path*."""
    events = _load_events(log_path)
    report_path.write_text(_render(events), encoding="utf-8")


def generate_findings_report(log_path: Path, report_path: Path) -> None:
    """Read *log_path* (NDJSON) and write the security findings HTML to *report_path*."""
    events = _load_events(log_path)
    report_path.write_text(_render_findings(events), encoding="utf-8")


# =============================================================================
# Helpers
# =============================================================================

def _load_events(path: Path) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def _e(text: str) -> str:
    return html.escape(str(text), quote=True)


def _ts(ts: str) -> str:
    try:
        t = ts.split("T")[1][:8]
        return f'<span class="ts">{_e(t)}</span>'
    except (IndexError, AttributeError):
        return ""


def _trunc(text: str) -> tuple[str, bool]:
    """Return (text, was_truncated)."""
    s = str(text)
    if len(s) <= _MAX_LEN:
        return s, False
    return s[:_MAX_LEN], True


# =============================================================================
# Event renderers
# =============================================================================

def _render_message(msg: dict) -> str:
    role = msg.get("role", "unknown")
    content = msg.get("content", "")
    tool_calls = msg.get("tool_calls", [])
    name = msg.get("name", "")

    label = f"{role} ({name})" if name else role
    parts = [f'<div class="msg {_e(role)}">']
    parts.append(f'<div class="msg-role">{_e(label)}</div>')

    if content:
        trimmed, was_cut = _trunc(str(content))
        parts.append(f'<div class="msg-content">{_e(trimmed)}</div>')
        if was_cut:
            parts.append('<div class="truncated">⚠ output truncated in report — see audit.ndjson for full content</div>')

    if tool_calls:
        parts.append('<div class="msg-tool-calls">')
        for tc in tool_calls:
            tc_name = tc.get("name", "")
            tc_args = json.dumps(tc.get("args", {}), indent=2)
            parts.append(
                f'<div class="tool-call-chip">'
                f'<span class="tc-name">{_e(tc_name)}</span>'
                f'<pre>{_e(tc_args)}</pre>'
                f'</div>'
            )
        parts.append('</div>')

    parts.append('</div>')
    return "".join(parts)


def _render_llm_request(ev: dict) -> str:
    data = ev.get("data", {})
    model = data.get("model", "unknown")
    messages = data.get("messages", [])
    ts = _ts(ev.get("ts", ""))
    inner = "\n".join(_render_message(m) for m in messages)
    return (
        f'<details class="ev ev-llm-req">'
        f'<summary>🤖 LLM Request &nbsp;<code>{_e(model)}</code>'
        f'&nbsp;<span class="badge badge-blue">{len(messages)} msg</span>'
        f'&nbsp;{ts}</summary>'
        f'<div class="inner"><div class="messages">{inner}</div></div>'
        f'</details>'
    )


def _render_llm_response(ev: dict) -> str:
    data = ev.get("data", {})
    generations = data.get("generations", [])
    usage = data.get("usage") or {}
    ts = _ts(ev.get("ts", ""))
    inner = "\n".join(_render_message(g) for g in generations)

    usage_html = ""
    if usage:
        items = ", ".join(f"{k}: {v}" for k, v in usage.items())
        usage_html = f'<div class="token-usage">Tokens — {_e(items)}</div>'

    return (
        f'<details class="ev ev-llm-resp">'
        f'<summary>💬 LLM Response &nbsp;{ts}</summary>'
        f'<div class="inner"><div class="messages">{inner}</div>{usage_html}</div>'
        f'</details>'
    )


def _render_tool_call(ev: dict) -> str:
    data = ev.get("data", {})
    name = data.get("name", "unknown")
    input_str = data.get("input", "")
    ts = _ts(ev.get("ts", ""))
    trimmed, was_cut = _trunc(str(input_str))
    trunc_note = '<div class="truncated">⚠ truncated</div>' if was_cut else ""
    return (
        f'<details class="ev ev-tool-call">'
        f'<summary>🔧 Tool Call &nbsp;<code>{_e(name)}</code>&nbsp;{ts}</summary>'
        f'<div class="inner">'
        f'<div class="label">Input</div>'
        f'<pre class="code-block">{_e(trimmed)}</pre>{trunc_note}'
        f'</div></details>'
    )


def _render_tool_result(ev: dict) -> str:
    data = ev.get("data", {})
    output = data.get("output", "")
    ts = _ts(ev.get("ts", ""))
    trimmed, was_cut = _trunc(str(output))
    trunc_note = '<div class="truncated">⚠ output truncated — see audit.ndjson for full content</div>' if was_cut else ""
    return (
        f'<details class="ev ev-tool-result">'
        f'<summary>✅ Tool Result &nbsp;{ts}</summary>'
        f'<div class="inner">'
        f'<pre class="code-block">{_e(trimmed)}</pre>{trunc_note}'
        f'</div></details>'
    )


def _render_tool_error(ev: dict) -> str:
    data = ev.get("data", {})
    error = data.get("error", "")
    ts = _ts(ev.get("ts", ""))
    return (
        f'<details class="ev ev-tool-error">'
        f'<summary>❌ Tool Error &nbsp;{ts}</summary>'
        f'<div class="inner"><pre class="code-block">{_e(str(error))}</pre></div>'
        f'</details>'
    )


_RENDERERS = {
    "llm_request": _render_llm_request,
    "llm_response": _render_llm_response,
    "tool_call": _render_tool_call,
    "tool_result": _render_tool_result,
    "tool_error": _render_tool_error,
}


def _render_events(events: list[dict]) -> str:
    parts = []
    for ev in events:
        renderer = _RENDERERS.get(ev.get("type", ""))
        if renderer:
            parts.append(renderer(ev))
    return "\n".join(parts) or '<p class="empty">No events recorded.</p>'


# =============================================================================
# Segmentation
# =============================================================================

def _segment(events: list[dict]) -> list[dict]:
    """Group events into logical segments: planner, step-N, reporter."""
    segments: list[dict] = []
    current: dict | None = None
    step_index = 0

    for ev in events:
        if ev["type"] != "node_enter":
            if current is not None:
                current["events"].append(ev)
            continue

        node = ev.get("data", {}).get("node", "")

        if node == "planner":
            current = {"type": "planner", "events": []}
            segments.append(current)

        elif node == "executor":
            # Find an existing step segment for this step_index
            existing = next(
                (s for s in segments if s["type"] == "step" and s["step_index"] == step_index),
                None,
            )
            if existing:
                current = existing  # keep appending into same step
            else:
                # Flush planner if it's the first executor visit
                current = {"type": "step", "step_index": step_index, "events": []}
                segments.append(current)

        elif node == "tools":
            pass  # tools events go into the current step segment

        elif node == "advance":
            step_index += 1
            # advance has no interesting events; park future events nowhere
            current = None

        elif node == "reporter":
            current = {"type": "reporter", "events": []}
            segments.append(current)

    return segments


# =============================================================================
# Top-level renderer
# =============================================================================

def _render(events: list[dict]) -> str:
    start_ev = next((e for e in events if e["type"] == "assessment_start"), None)
    plan_ev = next((e for e in events if e["type"] == "plan_created"), None)
    done_ev = next((e for e in events if e["type"] == "assessment_complete"), None)

    # Metadata
    objective = "Security Assessment"
    provider = model = start_ts = duration = ""
    if start_ev:
        d = start_ev["data"]
        objective = d.get("objective", objective)
        provider = d.get("provider", "")
        model = d.get("model", "")
        start_ts = start_ev.get("ts", "")[:19].replace("T", " ") + " UTC"
    if done_ev:
        secs = int(done_ev["data"].get("duration_s", 0))
        m, s = divmod(secs, 60)
        duration = f"{m}m {s}s" if m else f"{s}s"

    steps: list[str] = plan_ev["data"].get("steps", []) if plan_ev else []

    segments = _segment(events)

    # ---- build nav + sections ----
    nav_parts: list[str] = [
        '<a class="nav-item" href="#summary">📊 Summary</a>',
        '<a class="nav-item" href="#plan">📋 Assessment Plan</a>',
        '<div class="nav-group-title">Execution</div>',
    ]
    section_parts: list[str] = []

    # Summary card
    meta_rows = ""
    for label, val in [
        ("Provider", provider), ("Model", model),
        ("Started", start_ts), ("Duration", duration),
    ]:
        if val:
            meta_rows += f"<tr><td>{_e(label)}</td><td>{_e(val)}</td></tr>"

    section_parts.append(
        f'<section class="card header-card" id="summary">'
        f'<h1>macOS Security Assessment</h1>'
        f'<p class="objective">{_e(objective)}</p>'
        f'<table class="meta-table"><tbody>{meta_rows}</tbody></table>'
        f'</section>'
    )

    # Plan card
    if steps:
        items = "".join(
            f'<li class="plan-item">'
            f'<span class="plan-num">{i+1}</span>'
            f'<span class="plan-text">{_e(s)}</span>'
            f'</li>'
            for i, s in enumerate(steps)
        )
        section_parts.append(
            f'<section class="card" id="plan">'
            f'<h2>Assessment Plan <span class="badge badge-slate">{len(steps)} steps</span></h2>'
            f'<ol class="plan-list">{items}</ol>'
            f'</section>'
        )
    else:
        section_parts.append(
            '<section class="card" id="plan"><h2>Assessment Plan</h2>'
            '<p class="empty">No plan recorded.</p></section>'
        )

    # Execution segments
    for seg in segments:
        st = seg["type"]
        evs = seg["events"]
        llm_n = sum(1 for e in evs if e["type"] == "llm_request")
        tool_n = sum(1 for e in evs if e["type"] == "tool_call")

        if st == "planner":
            sid = "planner"
            title = "🤔 Planner"
            badge = f"{llm_n} LLM call{'s' if llm_n != 1 else ''}"
            nav_parts.append(f'<a class="nav-item" href="#planner">Planner</a>')

        elif st == "step":
            idx = seg["step_index"]
            step_label = steps[idx] if idx < len(steps) else f"Step {idx + 1}"
            short = (step_label[:55] + "…") if len(step_label) > 55 else step_label
            sid = f"step-{idx}"
            title = f"Step {idx + 1}: {_e(step_label)}"
            badge = f"{llm_n} LLM · {tool_n} tool{'s' if tool_n != 1 else ''}"
            nav_parts.append(
                f'<a class="nav-item" href="#{_e(sid)}">'
                f'<span class="step-num-pill">{idx+1}</span> {_e(short)}</a>'
            )

        elif st == "reporter":
            sid = "final-report"
            title = "📋 Final Report"
            badge = f"{llm_n} LLM call{'s' if llm_n != 1 else ''}"
            nav_parts.append('<div class="nav-group-title">Report</div>')
            nav_parts.append('<a class="nav-item" href="#final-report">Final Report</a>')

        else:
            continue

        events_html = _render_events(evs)
        section_parts.append(
            f'<section class="card" id="{_e(sid)}">'
            f'<h2>{title} <span class="badge badge-slate">{_e(badge)}</span></h2>'
            f'<div class="section-controls">'
            f'<button class="btn-sm" onclick="expandSection(\'{_e(sid)}\')">Expand all</button>'
            f'<button class="btn-sm" onclick="collapseSection(\'{_e(sid)}\')">Collapse all</button>'
            f'</div>'
            f'{events_html}'
            f'</section>'
        )

    nav_html = "\n".join(nav_parts)
    body_html = "\n".join(section_parts)

    return _PAGE_TEMPLATE.format(
        title=_e(objective),
        css=_CSS,
        js=_JS,
        nav=nav_html,
        body=body_html,
    )


# =============================================================================
# Assets
# =============================================================================

_CSS = """
:root {
  --blue:#3b82f6; --green:#10b981; --amber:#f59e0b;
  --cyan:#06b6d4; --red:#ef4444;
  --slate-50:#f8fafc; --slate-100:#f1f5f9;
  --slate-800:#1e293b; --slate-900:#0f172a;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: var(--slate-100); color: #1e293b; line-height: 1.5; }

/* Layout */
.layout { display: flex; min-height: 100vh; }
.sidebar { width: 290px; min-width: 290px; background: var(--slate-900);
           color: #e2e8f0; padding: 1.25rem; position: sticky; top: 0;
           height: 100vh; overflow-y: auto; flex-shrink: 0; }
.main { flex: 1; padding: 2rem; max-width: 960px; }

/* Sidebar */
.sidebar .logo { font-size: 1rem; font-weight: 700; color: #f8fafc;
                 margin-bottom: 1.25rem; letter-spacing: .025em; }
.sidebar .logo span { color: var(--blue); }
.global-controls { display: flex; gap: .4rem; margin-bottom: 1.25rem; flex-wrap: wrap; }
.btn-global { padding: .2rem .6rem; border: 1px solid #334155; border-radius: 4px;
              background: #1e293b; color: #94a3b8; cursor: pointer;
              font-size: .75rem; transition: all .15s; }
.btn-global:hover { background: #334155; color: #f8fafc; }
.nav-group-title { font-size: .65rem; text-transform: uppercase;
                   letter-spacing: .1em; color: #64748b;
                   margin: 1rem 0 .35rem; padding-left: .25rem; }
.nav-item { display: flex; align-items: center; gap: .5rem;
            padding: .35rem .6rem; color: #94a3b8; text-decoration: none;
            border-radius: 6px; font-size: .82rem; transition: all .15s;
            margin-bottom: 2px; }
.nav-item:hover, .nav-item.active { background: #1e293b; color: #f8fafc; }
.step-num-pill { background: #334155; color: #cbd5e0; border-radius: 9999px;
                 width: 18px; height: 18px; display: flex; align-items: center;
                 justify-content: center; font-size: .65rem; font-weight: 700;
                 flex-shrink: 0; }

/* Cards */
.card { background: #fff; border-radius: 10px; padding: 1.5rem;
        margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.header-card { border-left: 4px solid var(--blue); }
.header-card h1 { font-size: 1.35rem; margin-bottom: .35rem; }
.objective { font-size: .95rem; color: #475569; margin: .35rem 0 .75rem; }
.meta-table { border-collapse: collapse; font-size: .84rem; }
.meta-table td { padding: .2rem 1rem .2rem 0; color: #64748b; }
.meta-table td:first-child { font-weight: 600; color: #334155; width: 80px; }
.card h2 { font-size: 1rem; font-weight: 600; margin-bottom: .9rem;
           display: flex; align-items: center; gap: .5rem; }

/* Plan */
.plan-list { list-style: none; }
.plan-item { display: flex; align-items: flex-start; gap: .75rem;
             padding: .45rem 0; border-bottom: 1px solid #f1f5f9; }
.plan-item:last-child { border-bottom: none; }
.plan-num { font-size: .7rem; background: #f1f5f9; color: #64748b;
            border-radius: 50%; width: 22px; height: 22px; display: flex;
            align-items: center; justify-content: center;
            flex-shrink: 0; font-weight: 700; margin-top: 1px; }
.plan-text { font-size: .88rem; color: #334155; }

/* Collapsibles */
details { border: 1px solid #e2e8f0; border-radius: 8px;
          margin-bottom: .45rem; overflow: hidden; }
details summary { padding: .55rem 1rem; cursor: pointer; user-select: none;
                  font-size: .84rem; font-weight: 500; list-style: none;
                  display: flex; align-items: center; gap: .45rem; }
details summary::-webkit-details-marker { display: none; }
details summary::before { content: '▶'; font-size: .65rem; color: #94a3b8;
                           transition: transform .18s; flex-shrink: 0; }
details[open] summary::before { transform: rotate(90deg); }
details summary:hover { background: #f8fafc; }
details[open] summary { background: #f8fafc; border-bottom: 1px solid #e2e8f0; }
details .inner { padding: .9rem 1rem; }

/* Event border colours */
.ev-llm-req summary  { border-left: 3px solid var(--blue); }
.ev-llm-resp summary { border-left: 3px solid var(--green); }
.ev-tool-call summary   { border-left: 3px solid var(--amber); }
.ev-tool-result summary { border-left: 3px solid var(--cyan); }
.ev-tool-error summary  { border-left: 3px solid var(--red); }

/* Messages */
.messages { display: flex; flex-direction: column; gap: .45rem; }
.msg { border-radius: 6px; padding: .65rem .8rem; font-size: .8rem; }
.msg-role { font-size: .63rem; text-transform: uppercase; letter-spacing: .08em;
            font-weight: 700; margin-bottom: .3rem; }
.msg-content { white-space: pre-wrap; word-break: break-word;
               font-family: 'SF Mono', Monaco, Consolas, monospace;
               line-height: 1.55; }
.msg.system { background: #f0fdf4; border-left: 3px solid #86efac; }
.msg.system .msg-role { color: #16a34a; }
.msg.human  { background: #eff6ff; border-left: 3px solid #93c5fd; }
.msg.human  .msg-role { color: #1d4ed8; }
.msg.ai     { background: #faf5ff; border-left: 3px solid #c4b5fd; }
.msg.ai     .msg-role { color: #7c3aed; }
.msg.tool   { background: #fffbeb; border-left: 3px solid #fcd34d; }
.msg.tool   .msg-role { color: #d97706; }
.msg-tool-calls { margin-top: .5rem; }
.tool-call-chip { background: #fef3c7; border: 1px solid #fde68a;
                  border-radius: 4px; padding: .35rem .6rem;
                  font-size: .75rem; margin-top: .25rem; }
.tool-call-chip .tc-name { font-weight: 700; color: #92400e;
                            font-family: 'SF Mono', monospace; }
.tool-call-chip pre { margin-top: .25rem; white-space: pre-wrap;
                      word-break: break-word; font-size: .72rem; color: #78350f; }

/* Code */
pre.code-block { background: #0f172a; color: #e2e8f0; padding: .9rem;
                 border-radius: 6px; font-family: 'SF Mono', Monaco, Consolas, monospace;
                 font-size: .77rem; overflow-x: auto; white-space: pre-wrap;
                 word-break: break-word; line-height: 1.55; }
.label { font-size: .72rem; text-transform: uppercase; letter-spacing: .07em;
         font-weight: 600; color: #64748b; margin-bottom: .4rem; }

/* Badges */
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 9999px;
         font-size: .68rem; font-weight: 600; }
.badge-blue  { background: #dbeafe; color: #1d4ed8; }
.badge-slate { background: #f1f5f9; color: #475569; }

/* Token usage */
.token-usage { font-size: .74rem; color: #64748b; margin-top: .6rem;
               padding: .4rem .6rem; background: #f8fafc; border-radius: 4px; }

/* Controls */
.section-controls { margin-bottom: .65rem; display: flex; gap: .4rem; }
.btn-sm { padding: .2rem .6rem; border: 1px solid #e2e8f0; border-radius: 4px;
          background: #fff; cursor: pointer; font-size: .77rem; color: #475569;
          transition: all .15s; }
.btn-sm:hover { background: #f1f5f9; border-color: #cbd5e1; }

/* Misc */
.ts { font-family: monospace; font-size: .68rem; color: #94a3b8; margin-left: auto; }
.truncated { color: #d97706; font-size: .7rem; margin-top: .3rem; }
.empty { color: #94a3b8; font-size: .875rem; font-style: italic; }
"""

_JS = """
function expandSection(id) {
  document.getElementById(id).querySelectorAll('details').forEach(d => d.open = true);
}
function collapseSection(id) {
  document.getElementById(id).querySelectorAll('details').forEach(d => d.open = false);
}
function expandAll() {
  document.querySelectorAll('details').forEach(d => d.open = true);
}
function collapseAll() {
  document.querySelectorAll('details').forEach(d => d.open = false);
}

// Highlight active nav item as you scroll
const navLinks = document.querySelectorAll('.nav-item[href^="#"]');
const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      navLinks.forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + entry.target.id));
    }
  });
}, { rootMargin: '-20% 0px -70% 0px' });
document.querySelectorAll('section[id]').forEach(s => observer.observe(s));
"""

_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Assessment Report — {title}</title>
  <style>{css}</style>
</head>
<body>
<div class="layout">
  <nav class="sidebar">
    <div class="logo">mac<span>-assess</span></div>
    <div class="global-controls">
      <button class="btn-global" onclick="expandAll()">Expand all</button>
      <button class="btn-global" onclick="collapseAll()">Collapse all</button>
    </div>
    {nav}
  </nav>
  <main class="main">
    {body}
  </main>
</div>
<script>{js}</script>
</body>
</html>"""


# =============================================================================
# Findings report — pure security output
# =============================================================================

# Section names the reporter is prompted to produce, with display config:
# (match_fragment_lower, display_title, accent_colour)
_SECTION_DEFS = [
    ("executive summary",   "Executive Summary",    "#3b82f6"),  # blue
    ("critical findings",   "Critical Findings",    "#ef4444"),  # red
    ("credential exposure", "Credential Exposure",  "#f97316"),  # orange
    ("pivot opportunit",    "Pivot Opportunities",  "#eab308"),  # yellow
    ("data at risk",        "Data at Risk",         "#8b5cf6"),  # purple
    ("recommendation",      "Recommendations",      "#10b981"),  # green
]


def _extract_reporter_text(events: list[dict]) -> str | None:
    """Return the final reporter LLM response content, or None.

    LangGraph timing: callbacks fire *during* node execution, but the CLI
    writes node_enter *after* the stream yields (i.e. after the node finishes).
    So the reporter's llm_response appears BEFORE node_enter:reporter in the
    log. The reporter is always the last LLM call, so the last llm_response
    in the file is reliably the reporter's output.
    """
    last_content: str | None = None
    for ev in events:
        if ev["type"] == "llm_response":
            gens = ev.get("data", {}).get("generations", [])
            if gens:
                content = gens[0].get("content", "")
                if content:
                    last_content = content
    return last_content


def _inline_md(text: str) -> str:
    """Convert inline markdown (bold, italic, inline code) to HTML."""
    # Escape first, then apply inline transforms on the escaped text
    t = html.escape(text, quote=False)
    t = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', t)
    t = re.sub(r'\*(.+?)\*',     r'<em>\1</em>',         t)
    t = re.sub(r'`([^`]+)`',     r'<code>\1</code>',     t)
    return t


def _md_to_html(text: str) -> str:
    """Convert a markdown string to HTML, handling common structures."""
    lines = text.split("\n")
    out: list[str] = []
    in_list: str | None = None   # 'ul' or 'ol'
    in_code = False
    code_buf: list[str] = []
    pending_p: list[str] = []

    def flush_p() -> None:
        if pending_p:
            out.append(f'<p>{"<br>".join(pending_p)}</p>')
            pending_p.clear()

    def flush_list() -> None:
        nonlocal in_list
        flush_p()
        if in_list:
            out.append(f"</{in_list}>")
            in_list = None

    for raw in lines:
        # ── Code fence ────────────────────────────────────────────────────────
        if raw.startswith("```"):
            if in_code:
                out.append(f'<pre><code>{"".join(code_buf)}</code></pre>')
                code_buf.clear()
                in_code = False
            else:
                flush_list()
                in_code = True
            continue
        if in_code:
            code_buf.append(html.escape(raw) + "\n")
            continue

        line = raw.rstrip()

        # ── Headings ──────────────────────────────────────────────────────────
        if line.startswith("#### "):
            flush_list()
            out.append(f'<h4>{_inline_md(line[5:])}</h4>')
        elif line.startswith("### "):
            flush_list()
            out.append(f'<h3>{_inline_md(line[4:])}</h3>')
        elif line.startswith("## "):
            flush_list()
            out.append(f'<h2>{_inline_md(line[3:])}</h2>')
        elif line.startswith("# "):
            flush_list()
            out.append(f'<h1>{_inline_md(line[2:])}</h1>')

        # ── Horizontal rule ───────────────────────────────────────────────────
        elif line.strip() in ("---", "***", "___"):
            flush_list()
            out.append("<hr>")

        # ── Unordered list ────────────────────────────────────────────────────
        elif re.match(r'^[-*+] ', line):
            flush_p()
            if in_list != "ul":
                if in_list:
                    out.append(f"</{in_list}>")
                out.append("<ul>")
                in_list = "ul"
            out.append(f"<li>{_inline_md(line[2:])}</li>")

        # ── Ordered list ──────────────────────────────────────────────────────
        elif re.match(r'^\d+[.)]\s', line):
            flush_p()
            if in_list != "ol":
                if in_list:
                    out.append(f"</{in_list}>")
                out.append("<ol>")
                in_list = "ol"
            content = re.sub(r'^\d+[.)]\s+', '', line)
            out.append(f"<li>{_inline_md(content)}</li>")

        # ── Blank line ────────────────────────────────────────────────────────
        elif not line.strip():
            flush_list()

        # ── Paragraph text ────────────────────────────────────────────────────
        else:
            if in_list:
                # continuation inside a list item — append to last item
                if out and out[-1].endswith("</li>"):
                    out[-1] = out[-1][:-5] + " " + _inline_md(line) + "</li>"
            else:
                pending_p.append(_inline_md(line))

    flush_list()
    if in_code and code_buf:
        out.append(f'<pre><code>{"".join(code_buf)}</code></pre>')
    return "\n".join(out)


def _split_into_sections(md_text: str) -> list[dict]:
    """Split the reporter markdown into named sections based on ## headings."""
    sections: list[dict] = []
    current_title = ""
    current_lines: list[str] = []

    for line in md_text.split("\n"):
        # Match ## or ### headings as section boundaries
        m = re.match(r'^#{1,3}\s+(.+)', line)
        if m:
            if current_lines or current_title:
                sections.append({
                    "title": current_title,
                    "content": "\n".join(current_lines).strip(),
                })
            current_title = m.group(1).strip()
            current_lines = []
        else:
            current_lines.append(line)

    if current_title or current_lines:
        sections.append({
            "title": current_title,
            "content": "\n".join(current_lines).strip(),
        })

    return sections


def _section_colour(title: str) -> str:
    """Return the accent colour for a section based on its title."""
    tl = title.lower()
    for fragment, _, colour in _SECTION_DEFS:
        if fragment in tl:
            return colour
    return "#64748b"  # slate default


def _render_findings(events: list[dict]) -> str:
    """Render a clean security findings report from audit events."""
    # ── Metadata ──────────────────────────────────────────────────────────────
    start_ev  = next((e for e in events if e["type"] == "assessment_start"),   None)
    plan_ev   = next((e for e in events if e["type"] == "plan_created"),       None)
    done_ev   = next((e for e in events if e["type"] == "assessment_complete"), None)

    objective = "Security Assessment"
    provider = model = start_ts = duration = ""
    if start_ev:
        d = start_ev["data"]
        objective = d.get("objective", objective)
        provider  = d.get("provider", "")
        model     = d.get("model", "")
        start_ts  = start_ev.get("ts", "")[:19].replace("T", " ") + " UTC"
    if done_ev:
        secs = int(done_ev["data"].get("duration_s", 0))
        m, s = divmod(secs, 60)
        duration = f"{m}m {s}s" if m else f"{s}s"

    # ── Reporter content ──────────────────────────────────────────────────────
    report_md = _extract_reporter_text(events)
    if not report_md:
        body_html = '<p class="empty">No findings recorded — assessment may not have completed.</p>'
        sections_html = ""
    else:
        sections = _split_into_sections(report_md)

        # If there's preamble before the first heading, wrap it too
        section_cards: list[str] = []
        for sec in sections:
            colour   = _section_colour(sec["title"])
            title_h  = f'<h2 class="section-title">{_e(sec["title"])}</h2>' if sec["title"] else ""
            content  = _md_to_html(sec["content"]) if sec["content"] else ""
            if not title_h and not content:
                continue
            section_cards.append(
                f'<div class="finding-card" style="border-left-color:{colour}">'
                f'{title_h}{content}'
                f'</div>'
            )
        body_html = "\n".join(section_cards)

    # ── Meta info bar ─────────────────────────────────────────────────────────
    meta_items = " &nbsp;·&nbsp; ".join(
        v for v in [provider, model, start_ts, (f"⏱ {duration}" if duration else "")]
        if v
    )

    page = _FINDINGS_TEMPLATE.format(
        title=_e(objective),
        objective=_e(objective),
        meta=meta_items,
        body=body_html,
        css=_FINDINGS_CSS,
    )
    return page


_FINDINGS_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background: #f8fafc;
  color: #1e293b;
  line-height: 1.7;
  font-size: 15px;
}

/* ── Header ── */
.report-header {
  background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
  color: #f1f5f9;
  padding: 2.5rem 3rem 2rem;
  border-bottom: 4px solid #3b82f6;
}
.report-header .logo {
  font-size: .8rem;
  text-transform: uppercase;
  letter-spacing: .15em;
  color: #94a3b8;
  margin-bottom: .75rem;
}
.report-header h1 {
  font-size: 1.8rem;
  font-weight: 700;
  color: #f8fafc;
  margin-bottom: .5rem;
  line-height: 1.3;
}
.report-header .meta {
  font-size: .8rem;
  color: #94a3b8;
  margin-top: .5rem;
}

/* ── Main content ── */
.report-body {
  max-width: 900px;
  margin: 2.5rem auto;
  padding: 0 2rem 4rem;
}

/* ── Finding cards ── */
.finding-card {
  background: #ffffff;
  border-left: 5px solid #64748b;
  border-radius: 8px;
  padding: 1.75rem 2rem;
  margin-bottom: 1.5rem;
  box-shadow: 0 1px 4px rgba(0,0,0,.07);
}
.section-title {
  font-size: 1.05rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: #0f172a;
  margin-bottom: 1rem;
  padding-bottom: .5rem;
  border-bottom: 1px solid #e2e8f0;
}

/* ── Typography inside cards ── */
.finding-card p   { margin-bottom: .75rem; color: #334155; }
.finding-card p:last-child { margin-bottom: 0; }

.finding-card h1,
.finding-card h2  { font-size: 1rem; font-weight: 700; margin: 1.25rem 0 .5rem; color: #0f172a; }
.finding-card h3  { font-size: .95rem; font-weight: 600; margin: 1rem 0 .4rem; color: #1e293b; }
.finding-card h4  { font-size: .9rem; font-weight: 600; margin: .9rem 0 .35rem; color: #334155; }

.finding-card ul,
.finding-card ol  { padding-left: 1.4rem; margin-bottom: .75rem; }
.finding-card li  { margin-bottom: .3rem; color: #334155; }

.finding-card strong { color: #0f172a; }
.finding-card em     { color: #475569; }

.finding-card code {
  background: #f1f5f9;
  border: 1px solid #e2e8f0;
  border-radius: 3px;
  padding: .1em .35em;
  font-family: 'SF Mono', Monaco, Consolas, monospace;
  font-size: .82em;
  color: #dc2626;
}
.finding-card pre {
  background: #0f172a;
  color: #e2e8f0;
  border-radius: 6px;
  padding: 1rem;
  overflow-x: auto;
  font-family: 'SF Mono', Monaco, Consolas, monospace;
  font-size: .8rem;
  line-height: 1.55;
  margin: .75rem 0;
}
.finding-card pre code {
  background: none;
  border: none;
  padding: 0;
  color: inherit;
  font-size: inherit;
}
.finding-card hr {
  border: none;
  border-top: 1px solid #e2e8f0;
  margin: 1rem 0;
}

/* ── Footer ── */
.report-footer {
  text-align: center;
  font-size: .75rem;
  color: #94a3b8;
  padding: 2rem;
  border-top: 1px solid #e2e8f0;
  margin-top: 2rem;
}

.empty { color: #94a3b8; font-style: italic; padding: 2rem; text-align: center; }

@media print {
  body { background: #fff; }
  .report-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .finding-card { box-shadow: none; break-inside: avoid; }
}
"""

_FINDINGS_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Findings — {title}</title>
  <style>{css}</style>
</head>
<body>
  <header class="report-header">
    <div class="logo">mac-assess &nbsp;/&nbsp; Security Findings Report</div>
    <h1>{objective}</h1>
    <div class="meta">{meta}</div>
  </header>
  <main class="report-body">
    {body}
  </main>
  <footer class="report-footer">
    Generated by mac-assess &nbsp;·&nbsp; Handle this report with care — it may contain sensitive information.
  </footer>
</body>
</html>"""
