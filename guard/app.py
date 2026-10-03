"""
SecureAI - secured chat interface.

UI only. Every prompt is checked by the Guard before it reaches the AI, and
every AI reply is checked by the Guard before it is shown. All Guard and LLM
calls live in engine.py.
"""

from __future__ import annotations

import html

import streamlit as st

from engine import ConfigError, load_config, secure_turn

APP_TITLE = "SecureAI"

st.set_page_config(
    page_title=APP_TITLE,
    layout="wide",
    initial_sidebar_state="expanded",
)

_CSS = """
<style>
    #MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDeployButton"],
    [data-testid="stStatusWidget"], [data-testid="stDecoration"] { display: none !important; }
    header[data-testid="stHeader"] { background: transparent; }

    .stApp { background-color: #212121; }
    section[data-testid="stSidebar"] { background-color: #171717; }
    .block-container { max-width: 820px; padding-top: 2rem; padding-bottom: 6rem; }

    .brand { font-size: 1.25rem; font-weight: 600; letter-spacing: 0.01em; margin-bottom: 0.75rem; }
    .empty-state { text-align: center; margin-top: 22vh; }
    .empty-state h1 { font-size: 2rem; font-weight: 600; margin-bottom: 0.4rem; }
    .empty-state p { color: #9b9b9b; font-size: 1rem; }

    .notice {
        border-radius: 8px; padding: 10px 14px; border-left: 4px solid; font-size: 0.95rem;
    }
    .notice.blocked { background: rgba(248, 81, 73, 0.10); border-left-color: #f85149; color: #ffb4ae; }
    .notice.error   { background: rgba(210, 153, 34, 0.10); border-left-color: #d29922; color: #f0cf7a; }
    .notice .why { margin-top: 4px; font-size: 0.85rem; opacity: 0.85; }

    div[data-testid="stChatInput"] { border-radius: 24px; }
</style>
"""
st.markdown(_CSS, unsafe_allow_html=True)


# ----------------------------------------------------------------------
# Session state
# ----------------------------------------------------------------------

def _init_state() -> None:
    # Each message: {"role", "content", "kind": "normal" | "blocked" | "error",
    #                "detail": str, "in_context": bool}
    # Only messages with in_context=True are ever sent back to the AI.
    if "messages" not in st.session_state:
        st.session_state.messages = []


def _context_history() -> list[dict[str, str]]:
    return [
        {"role": m["role"], "content": m["content"]}
        for m in st.session_state.messages
        if m.get("in_context")
    ]


# ----------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------

def _notice(kind: str, text: str, detail: str = "") -> None:
    why = f'<div class="why">{html.escape(detail)}</div>' if detail else ""
    st.markdown(
        f'<div class="notice {kind}">{html.escape(text)}{why}</div>',
        unsafe_allow_html=True,
    )


def _render_message(msg: dict) -> None:
    with st.chat_message(msg["role"]):
        kind = msg.get("kind", "normal")
        if kind == "normal":
            st.markdown(msg["content"])
        else:
            _notice(kind, msg["content"], msg.get("detail", ""))


def _blocked_detail(detail: str) -> str:
    return f"Flagged: {detail}" if detail else ""


# ----------------------------------------------------------------------
# Chat turn
# ----------------------------------------------------------------------

def _handle_prompt(cfg, prompt_text: str) -> None:
    user_msg = {"role": "user", "content": prompt_text, "kind": "normal", "detail": "", "in_context": False}
    st.session_state.messages.append(user_msg)
    _render_message(user_msg)

    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            result = secure_turn(cfg, _context_history(), prompt_text)

        if result.status == "ok":
            st.markdown(result.reply)
            user_msg["in_context"] = True
            st.session_state.messages.append(
                {"role": "assistant", "content": result.reply, "kind": "normal", "detail": "", "in_context": True}
            )
        elif result.status in ("blocked_prompt", "blocked_response"):
            detail = _blocked_detail(result.detail)
            _notice("blocked", result.reply, detail)
            st.session_state.messages.append(
                {"role": "assistant", "content": result.reply, "kind": "blocked", "detail": detail, "in_context": False}
            )
        else:
            message = result.detail or "Something went wrong. Please try again."
            _notice("error", message)
            st.session_state.messages.append(
                {"role": "assistant", "content": message, "kind": "error", "detail": "", "in_context": False}
            )


# ----------------------------------------------------------------------
# Layout
# ----------------------------------------------------------------------

def _render_sidebar() -> None:
    with st.sidebar:
        st.markdown(f'<div class="brand">{APP_TITLE}</div>', unsafe_allow_html=True)
        if st.button("New chat", use_container_width=True):
            st.session_state.messages = []
            st.rerun()


def _render_setup_error(message: str) -> None:
    st.markdown(
        '<div class="empty-state"><h1>Setup required</h1>'
        "<p>SecureAI cannot start until the configuration is complete.</p></div>",
        unsafe_allow_html=True,
    )
    st.error(message)
    st.markdown(
        "Create a `.env` file next to `app.py` with:\n\n"
        "```\nGUARD_URL=...\nGUARD_TOKEN=...\nLLM_API_KEY=...\n```\n"
        "Then reload this page."
    )


def main() -> None:
    _init_state()
    _render_sidebar()

    try:
        cfg = load_config()
    except ConfigError as exc:
        _render_setup_error(str(exc))
        return

    prompt = st.chat_input(f"Message {APP_TITLE}")
    submitted = bool(prompt and prompt.strip())

    if not st.session_state.messages and not submitted:
        st.markdown(
            '<div class="empty-state"><h1>How can I help you today?</h1></div>',
            unsafe_allow_html=True,
        )

    for msg in st.session_state.messages:
        _render_message(msg)

    if submitted:
        _handle_prompt(cfg, prompt.strip())


main()
