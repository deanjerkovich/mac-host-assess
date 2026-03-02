"""HTML report generation from NDJSON audit logs.

Reads an audit log produced by AuditLog and generates a single self-contained
HTML file with collapsible sections, a sticky navigation sidebar, and
colour-coded event types.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

_MAX_LEN = 8000  # chars to show per output before truncating in HTML


# =============================================================================
# Public API
# =============================================================================

def generate_report(log_path: Path, report_path: Path) -> None:
    """Read *log_path* (NDJSON) and write a self-contained HTML to *report_path*."""
    events = _load_events(log_path)
    report_path.write_text(_render(events), encoding="utf-8")


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
