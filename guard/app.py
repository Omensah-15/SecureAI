"""
SecureAI - secured chat interface.
"""

from __future__ import annotations

import html

import streamlit as st

from engine import ConfigError, load_config, secure_turn

APP_TITLE = "SecureAI"

st.set_page_config(
    page_title=APP_TITLE,
    page_icon="\U0001F512",
    layout="wide",
    initial_sidebar_state="auto",
)

# The whole look is defined here so it does not depend on a .streamlit/config.toml
# being found, or on the visitor's browser being in light or dark mode.
_CSS = """
<style>
    :root { color-scheme: dark; }

    /* ---------- base ---------- */
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] { background-color: #212121; color: #ececec; }
    html, body, .stApp {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    .stApp p, .stApp li, .stApp label, .stApp h1, .stApp h2, .stApp h3, .stApp h4,
    .stApp [data-testid="stMarkdownContainer"], .stApp [data-testid="stCaptionContainer"] { color: #ececec; }

    /* Streamlit chrome we do not need. The header stays (it holds the sidebar toggle) but is invisible. */
    #MainMenu, footer, .stAppDeployButton, [data-testid="stDeployButton"],
    [data-testid="stStatusWidget"], [data-testid="stDecoration"] { display: none !important; }
    [data-testid="stHeader"] { background: transparent; }

    /* centred conversation column */
    [data-testid="stMainBlockContainer"], .block-container {
        max-width: 780px; padding: 2.5rem 1.25rem 9rem 1.25rem; margin: 0 auto;
    }

    /* ---------- sidebar ---------- */
    section[data-testid="stSidebar"] { background-color: #171717; border-right: 1px solid #262626; }
    section[data-testid="stSidebar"] * { color: #ececec; }
    .brand { display: flex; align-items: center; gap: 10px; font-size: 1.05rem; font-weight: 600; margin: 4px 0 14px 2px; }
    .brand-icon {
        width: 30px; height: 30px; border-radius: 8px; display: flex; align-items: center; justify-content: center;
        background: #10a37f; font-size: 15px;
    }
    .side-label { font-size: 0.72rem; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; color: #8e8e8e !important; margin: 18px 0 6px 4px; }
    .side-item {
        font-size: 0.88rem; padding: 7px 10px; border-radius: 8px; color: #d1d1d1 !important;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .side-item:hover { background: #212121; }
    .side-empty { font-size: 0.85rem; color: #8e8e8e !important; padding: 4px 10px; }
    .side-foot { font-size: 0.75rem; line-height: 1.45; color: #8e8e8e !important; padding: 12px 4px 0 4px; border-top: 1px solid #262626; margin-top: 18px; }
    section[data-testid="stSidebar"] [data-testid="stElementContainer"]:has([data-testid="stButton"]),
    section[data-testid="stSidebar"] [data-testid="stButton"],
    section[data-testid="stSidebar"] [data-testid="stButton"] > button { width: 100% !important; }

    /* ---------- buttons ---------- */
    [data-testid^="stBaseButton"] {
        background: #2f2f2f; color: #ececec; border: 1px solid #3a3a3a; border-radius: 10px;
        font-weight: 500; transition: background .15s ease, border-color .15s ease;
    }
    [data-testid^="stBaseButton"]:hover { background: #3a3a3a; border-color: #4a4a4a; color: #ffffff; }
    [data-testid^="stBaseButton"]:focus-visible { outline: 2px solid #10a37f; outline-offset: 1px; }
    [data-testid^="stBaseButton"] p { color: inherit; }

    /* ---------- chat messages ---------- */
    [data-testid="stChatMessage"] { background: transparent; padding: 0.6rem 0; gap: 0.9rem; align-items: flex-start; }
    [data-testid="stChatMessageContent"] { color: #ececec; min-width: 0; }
    [data-testid="stChatMessageContent"] p { line-height: 1.7; font-size: 1rem; }

    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) { flex-direction: row-reverse; }
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) [data-testid="stChatMessageAvatarUser"] { display: none; }
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) [data-testid="stChatMessageContent"] {
        flex: 0 1 auto; max-width: 82%; margin-left: auto; margin-right: 0; background: #2f2f2f;
        border-radius: 20px; padding: 0.6rem 1.1rem; overflow-wrap: anywhere;
    }
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) [data-testid="stMarkdownContainer"],
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) [data-testid="stMarkdownContainer"] p { margin: 0; }
    [data-testid="stChatMessageAvatarAssistant"] { background: #10a37f; color: #ffffff; border-radius: 50%; }

    /* ---------- composer ---------- */
    [data-testid="stBottom"], [data-testid="stBottom"] > div, [data-testid="stBottomBlockContainer"] { background: #212121; }
    [data-testid="stBottomBlockContainer"] { max-width: 780px; padding-bottom: 0.4rem; }
    [data-testid="stBottomBlockContainer"]::after {
        content: "SecureAI checks every prompt and reply. Review important information before relying on it.";
        display: block; text-align: center; font-size: 0.72rem; color: #8e8e8e; padding: 8px 0 6px 0;
    }
    [data-testid="stChatInput"] {
        background: #2f2f2f; border: 1px solid #3a3a3a; border-radius: 26px; box-shadow: 0 2px 12px rgba(0, 0, 0, .25);
    }
    [data-testid="stChatInput"]:focus-within { border-color: #5a5a5a !important; box-shadow: 0 2px 12px rgba(0, 0, 0, .25) !important; }
    [data-testid="stChatInput"] > div, [data-testid="stChatInput"] textarea {
        background: transparent; color: #ececec; border-radius: 26px; border-color: transparent !important;
        box-shadow: none !important; outline: none !important; caret-color: #ececec;
    }
    [data-testid="stChatInput"] textarea::placeholder { color: #9b9b9b; }
    [data-testid="stChatInputSubmitButton"] { border-radius: 50%; }

    /* ---------- welcome / setup screen ---------- */
    .empty-state { text-align: center; padding: 18vh 0 1.5rem 0; }
    .empty-icon {
        width: 56px; height: 56px; margin: 0 auto 18px auto; border-radius: 16px; display: flex; align-items: center;
        justify-content: center; background: #10a37f; font-size: 26px;
    }
    .empty-state h1 { font-size: 2rem; font-weight: 600; margin: 0 0 10px 0; padding: 0; color: #ececec; }
    .empty-state p { max-width: 460px; margin: 0 auto; color: #9b9b9b !important; font-size: 0.97rem; line-height: 1.6; }

    /* ---------- notices (blocked / error) ---------- */
    .notice {
        border-radius: 12px; padding: 11px 15px; border: 1px solid; font-size: 0.95rem; line-height: 1.55;
        overflow-wrap: anywhere;
    }
    .notice.blocked { background: rgba(248, 81, 73, 0.10);  border-color: rgba(248, 81, 73, 0.35);  color: #ff9d97; }
    .notice.error   { background: rgba(210, 153, 34, 0.10); border-color: rgba(210, 153, 34, 0.35); color: #f0cf7a; }
    .notice .why { margin-top: 4px; font-size: 0.85rem; opacity: 0.85; }

    /* ---------- rich content, alerts ---------- */
    [data-testid="stCode"], [data-testid="stCode"] pre, [data-testid="stMarkdownContainer"] pre { background: #171717 !important; border-radius: 10px; }
    [data-testid="stMarkdownContainer"] p code, [data-testid="stMarkdownContainer"] li code { background: #2f2f2f; color: #f0c674; padding: 2px 6px; border-radius: 6px; }
    [data-testid="stMarkdownContainer"] table { border-collapse: collapse; }
    [data-testid="stMarkdownContainer"] th, [data-testid="stMarkdownContainer"] td { border: 1px solid #3a3a3a; padding: 6px 12px; color: #ececec; }
    [data-testid="stMarkdownContainer"] th { background: #2a2a2a; }
    [data-testid="stMarkdownContainer"] a { color: #5fd3b3; }
    [data-testid="stAlert"] { border-radius: 12px; }
    [data-testid="stSpinner"] * { color: #9b9b9b; }

    /* ---------- small screens ---------- */
    @media (max-width: 640px) {
        [data-testid="stMainBlockContainer"], .block-container { padding: 3.2rem 0.75rem 8rem 0.75rem; }
        [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) [data-testid="stChatMessageContent"] { max-width: 92%; }
        .empty-state { padding-top: 12vh; }
        .empty-state h1 { font-size: 1.55rem; }
    }
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

def _fill_sidebar_history(slot) -> None:
    user_msgs = [m for m in st.session_state.messages if m["role"] == "user"]
    if not user_msgs:
        slot.markdown('<div class="side-empty">No messages yet</div>', unsafe_allow_html=True)
        return
    items = []
    for msg in user_msgs[-12:][::-1]:
        preview = " ".join(str(msg["content"]).split())
        preview = preview[:48] + ("..." if len(preview) > 48 else "")
        items.append(f'<div class="side-item">{html.escape(preview)}</div>')
    slot.markdown("".join(items), unsafe_allow_html=True)


def _render_sidebar():
    with st.sidebar:
        st.markdown(
            f'<div class="brand"><div class="brand-icon">\U0001F512</div>{html.escape(APP_TITLE)}</div>',
            unsafe_allow_html=True,
        )
        if st.button("+ New chat"):
            st.session_state.messages = []
            st.rerun()

        st.markdown('<div class="side-label">Current chat</div>', unsafe_allow_html=True)
        history_slot = st.empty()
        _fill_sidebar_history(history_slot)

        st.markdown(
            '<div class="side-foot">Every prompt and reply is checked by the Guard before it moves.</div>',
            unsafe_allow_html=True,
        )
    return history_slot


def _render_setup_error(message: str) -> None:
    st.markdown(
        '<div class="empty-state"><div class="empty-icon">\U0001F527</div><h1>Setup required</h1>'
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
    history_slot = _render_sidebar()

    try:
        cfg = load_config()
    except ConfigError as exc:
        _render_setup_error(str(exc))
        _fill_sidebar_history(history_slot)
        return

    prompt = st.chat_input(f"Message {APP_TITLE}")
    submitted = bool(prompt and prompt.strip())

    if not st.session_state.messages and not submitted:
        st.markdown(
            '<div class="empty-state"><div class="empty-icon">\U0001F512</div>'
            "<h1>How can I help you today?</h1>"
            "<p>Every message you send and every reply you receive is checked before it moves.</p></div>",
            unsafe_allow_html=True,
        )

    for msg in st.session_state.messages:
        _render_message(msg)

    if submitted:
        _handle_prompt(cfg, prompt.strip())

    _fill_sidebar_history(history_slot)  # refresh now that this run's messages exist


main()
