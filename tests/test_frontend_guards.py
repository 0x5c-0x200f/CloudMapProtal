"""Mistakes that jsdom cannot see but a real browser punishes."""
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "cloudmap_portal" / "portal" / "static"
JS, HTML = (STATIC / "app.js").read_text(), (STATIC / "index.html").read_text()


def svg_ids_with_hidden():
    return re.findall(r'<svg\b[^>]*?\bid="([\w-]+)"[^>]*?\shidden(?=[\s>])', HTML)       # a real attribute, not aria-hidden


def test_svg_elements_are_shown_and_hidden_through_the_attribute():
    """SVGElement has no `hidden` property (only HTMLElement does). `svg.hidden = false` silently does nothing, so an
    SVG that starts with the attribute stays invisible forever. This is how the Tree graph once showed nothing."""
    ids = svg_ids_with_hidden()
    assert ids, "expected the tree SVG to start hidden"
    for i in ids:
        assert not re.search(rf"\$\('#{i}'\)\.hidden\b", JS), f"#{i} is an SVG: use toggleAttribute('hidden', ...)"
        assert re.search(rf"\$\('#{i}'\)\.toggleAttribute\('hidden'", JS), f"#{i} is never shown through its attribute"


def test_agent_panel_is_wired_in():
    agent_js = (STATIC / "agent.js").read_text()
    assert '/static/agent.js' in HTML and 'id="tab-agent"' in HTML and 'id="agent"' in HTML
    assert "'agent'" in JS and "agentLoad" in JS, "app.js must load the agent after an import and switch to its tab"
    chat_js = (STATIC / "chat.js").read_text()
    assert '/static/chat.js' in HTML and 'id="chat-open"' in HTML and 'id="chat"' in HTML and 'id="chat-fab"' in HTML
    assert "/agent/chat" in chat_js and "agMd(" in chat_js and "esc(m.content)" in chat_js, "user text is escaped, bot text goes through agMd"
    assert "innerHTML" in agent_js and "esc(" in agent_js
    assert "esc(text)" in agent_js, "answers are escaped before markdown formatting"
