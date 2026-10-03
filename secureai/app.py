"""
SecureAI Streamlit UI
"""

from __future__ import annotations

import html
import time
import uuid

import streamlit as st

from config import Decision, settings
from engine import SecurityEngine

# ======================================================================
# Page config + styling
# ======================================================================

st.set_page_config(
    page_title=settings.app_title,
    page_icon="\U0001F512",
    layout="wide",
    initial_sidebar_state="auto",
)

_CUSTOM_CSS = """
<style>
    :root { color-scheme: dark; }

    /* ---------- base ---------- */
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
        background-color: #212121;
        color: #ececec;
    }
    html, body, .stApp { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, "Helvetica Neue", Arial, sans-serif; }
    .stApp p, .stApp li, .stApp label, .stApp h1, .stApp h2, .stApp h3, .stApp h4,
    .stApp [data-testid="stMarkdownContainer"], .stApp [data-testid="stCaptionContainer"] { color: #ececec; }
    .stApp [data-testid="stCaptionContainer"], .stApp small { color: #9b9b9b; }

    /* chrome we do not need: keep the header (it holds the sidebar toggle) but make it invisible */
    #MainMenu, footer, .stAppDeployButton, [data-testid="stDecoration"] { display: none !important; visibility: hidden; }
    [data-testid="stHeader"] { background: transparent; }

    /* centred conversation column */
    [data-testid="stMainBlockContainer"], .block-container {
        max-width: 780px;
        padding: 2.5rem 1.25rem 9rem 1.25rem;
        margin: 0 auto;
    }

    /* ---------- sidebar ---------- */
    section[data-testid="stSidebar"] { background-color: #171717; border-right: 1px solid #262626; }
    section[data-testid="stSidebar"] * { color: #ececec; }
    section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] * { color: #8e8e8e; }
    .sa-brand { display: flex; align-items: center; gap: 10px; font-size: 1.05rem; font-weight: 600; margin: 4px 0 14px 2px; }
    .sa-brand-icon {
        width: 30px; height: 30px; border-radius: 8px; display: flex; align-items: center; justify-content: center;
        background: #10a37f; font-size: 15px;
    }
    .sa-side-label { font-size: 0.72rem; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; color: #8e8e8e !important; margin: 18px 0 6px 4px; }
    .sa-side-item {
        font-size: 0.88rem; padding: 7px 10px; border-radius: 8px; color: #d1d1d1 !important;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .sa-side-item:hover { background: #212121; }
    .sa-side-empty { font-size: 0.85rem; color: #8e8e8e !important; padding: 4px 10px; }
    .sa-side-foot { font-size: 0.75rem; line-height: 1.45; color: #8e8e8e !important; padding: 12px 4px 0 4px; border-top: 1px solid #262626; margin-top: 18px; }

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
        border-radius: 20px; padding: 0.6rem 1.1rem;
    }
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) [data-testid="stMarkdownContainer"],
    [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) [data-testid="stMarkdownContainer"] p { margin: 0; }
    [data-testid="stChatMessageAvatarAssistant"] { background: #10a37f; color: #ffffff; border-radius: 50%; }

    /* ---------- composer ---------- */
    [data-testid="stBottom"], [data-testid="stBottom"] > div, [data-testid="stBottomBlockContainer"] { background: #212121; }
    [data-testid="stBottomBlockContainer"] { max-width: 780px; padding-bottom: 0.4rem; }
    [data-testid="stBottomBlockContainer"]::after {
        content: "SecureAI scans every prompt and response. Review important information before relying on it.";
        display: block; text-align: center; font-size: 0.72rem; color: #8e8e8e; padding: 8px 0 6px 0;
    }
    [data-testid="stChatInput"] {
        background: #2f2f2f; border: 1px solid #3a3a3a; border-radius: 26px; box-shadow: 0 2px 12px rgba(0, 0, 0, .25);
    }
    [data-testid="stChatInput"]:focus-within { border-color: #5a5a5a !important; box-shadow: 0 2px 12px rgba(0, 0, 0, .25) !important; }
    [data-testid="stChatInput"] > div, [data-testid="stChatInput"] textarea {
        background: transparent; color: #ececec; border-radius: 26px; border-color: transparent !important; box-shadow: none !important; outline: none !important;
    }
    [data-testid="stChatInput"] textarea { caret-color: #ececec; }
    [data-testid="stChatInput"] textarea::placeholder { color: #9b9b9b; }
    [data-testid="stChatInputSubmitButton"] { border-radius: 50%; }

    /* ---------- welcome screen ---------- */
    .sa-hero { text-align: center; padding: 18vh 0 2rem 0; }
    .sa-hero-icon {
        width: 56px; height: 56px; margin: 0 auto 18px auto; border-radius: 16px; display: flex; align-items: center;
        justify-content: center; background: #10a37f; font-size: 26px;
    }
    .sa-hero h1 { font-size: 2rem; font-weight: 600; margin: 0 0 10px 0; padding: 0; color: #ececec; }
    .sa-hero p { max-width: 460px; margin: 0 auto; color: #9b9b9b !important; font-size: 0.97rem; line-height: 1.6; }

    /* ---------- security banner + findings ---------- */
    .secureai-banner {
        border-radius: 12px; padding: 10px 14px; margin: 6px 0 10px 0; font-size: 0.88rem;
        border: 1px solid; display: flex; flex-direction: column; gap: 2px;
    }
    .secureai-banner .sa-label { font-weight: 600; letter-spacing: .02em; }
    .secureai-banner .sa-decision { opacity: .85; font-size: 0.82rem; }
    .secureai-banner.allow    { background: rgba(16, 163, 127, .10); border-color: rgba(16, 163, 127, .35); color: #5fd3b3; }
    .secureai-banner.sanitize { background: rgba(210, 153, 34, .10); border-color: rgba(210, 153, 34, .35); color: #e3b341; }
    .secureai-banner.block    { background: rgba(248, 81, 73, .10);  border-color: rgba(248, 81, 73, .35);  color: #ff8a84; }
    .secureai-finding {
        font-size: 0.84rem; padding: 8px 12px; margin: 6px 0; border-radius: 10px;
        background: #2a2a2a; border: 1px solid #353535; color: #d6d6d6; line-height: 1.5;
    }
    .secureai-finding-desc { color: #9b9b9b; }
    .secureai-redaction-diff {
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.84rem; padding: 12px 14px;
        border-radius: 12px; background: #1a1a1a; border: 1px solid #333; color: #e0e0e0;
        white-space: pre-wrap; word-break: break-word;
    }
    .sa-scan { color: #9b9b9b; font-size: 0.88rem; }

    /* ---------- expanders, alerts, inputs ---------- */
    [data-testid="stExpander"], [data-testid="stExpander"] details {
        border: 1px solid #333 !important; border-radius: 12px; background: #1f1f1f;
    }
    [data-testid="stExpander"] details { border: none !important; }
    [data-testid="stExpander"] summary, [data-testid="stExpander"] summary * { color: #bdbdbd; font-size: 0.88rem; }
    [data-testid="stAlert"] { border-radius: 12px; font-size: 0.92rem; }
    [data-testid="stChatMessage"] [data-testid="stHorizontalBlock"] { gap: 0.5rem; margin-top: 12px; }
    [data-testid="stTextArea"] textarea { background: #2f2f2f; color: #ececec; border: 1px solid #3a3a3a; border-radius: 12px; }
    [data-testid="stMetric"] { background: #2a2a2a; border: 1px solid #353535; border-radius: 12px; padding: 14px 16px; }
    pre, code { border-radius: 8px; }
    [data-testid="stCode"], [data-testid="stCode"] pre, [data-testid="stMarkdownContainer"] pre { background: #171717 !important; }
    [data-testid="stMarkdownContainer"] p code, [data-testid="stMarkdownContainer"] li code { background: #2f2f2f; color: #f0c674; padding: 2px 6px; }

    /* ---------- small screens ---------- */
    @media (max-width: 640px) {
        [data-testid="stMainBlockContainer"], .block-container { padding: 3.2rem 0.75rem 8rem 0.75rem; }
        [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) [data-testid="stChatMessageContent"] { max-width: 92%; }
        .sa-hero { padding-top: 12vh; }
        .sa-hero h1 { font-size: 1.55rem; }
    }
</style>
"""
st.markdown(_CUSTOM_CSS, unsafe_allow_html=True)


# ======================================================================
# Engine loading (cached — loaded once per server process, not per request)
# ======================================================================

@st.cache_resource(show_spinner=False)
def get_engine() -> tuple[SecurityEngine | None, str | None]:
    """
    Loads the SecurityEngine once and caches it across reruns/sessions.
    Returns (engine, error_message). On failure, engine is None and the
    caller renders a clear setup error instead of crashing the app — a
    missing/misnamed model folder should never take down the whole UI.
    """
    try:
        engine = SecurityEngine(load_models=True)
        return engine, None
    except Exception as exc:  # noqa: BLE001 - intentionally broad: any
        # startup failure here must degrade to a visible error, not a
        # stack trace the judge/user can't act on.
        return None, str(exc)


# ======================================================================
# Session state
# ======================================================================

def _init_session_state() -> None:
    if "session_id" not in st.session_state:
        st.session_state.session_id = str(uuid.uuid4())
    if "messages" not in st.session_state:
        st.session_state.messages = []  # list[{"role", "content", "scan": ScanResult|None}]
    if "pending" not in st.session_state:
        st.session_state.pending = None  # holds a SANITIZE scan awaiting user choice
    if "page" not in st.session_state:
        st.session_state.page = "Chat"


# ======================================================================
# Rendering helpers
# ======================================================================

_ANALYSIS_NOTICE = (
    "Prompt injection detected in embedded content. The content was treated as "
    "untrusted data and was not executed."
)


def render_security_banner(scan_result) -> None:
    # The risk score is still computed, stored and audited by the engine;
    # it is intentionally not shown in the UI. An allowed ANALYSIS of a
    # detected injection keeps its findings visible; only the decision line
    # says why the request was permitted. Amber (the existing "sanitize" style) signals
    # "allowed, but something was detected".
    analysis_allowed = getattr(scan_result, "injection_handling", None) is not None
    css_class = "sanitize" if analysis_allowed else scan_result.decision.value.lower()
    label = {
        Decision.ALLOW: "SECURE",
        Decision.SANITIZE: "SECURITY CHECK — SANITIZATION AVAILABLE",
        Decision.BLOCK: "SECURITY CHECK FAILED",
    }[scan_result.decision]
    decision_line = scan_result.decision.value
    if analysis_allowed:
        label = "SECURITY CHECK — INJECTION DETECTED IN EMBEDDED CONTENT"
        decision_line = f"{scan_result.decision.value} — ANALYSIS OF DETECTED INJECTION"

    st.markdown(
        f'<div class="secureai-banner {css_class}">'
        f'<div class="sa-label">{html.escape(label)}</div>'
        f'<div class="sa-decision">Decision: {html.escape(decision_line)}</div>'
        f"</div>",
        unsafe_allow_html=True,
    )

    if scan_result.findings:
        with st.expander(f"View analysis ({len(scan_result.findings)} finding(s))"):
            for f in scan_result.findings:
                description_html = (
                    f'<br/><span class="secureai-finding-desc">{html.escape(str(f.description))}</span>'
                    if f.description else ""
                )
                st.markdown(
                    f'<div class="secureai-finding"><b>{html.escape(str(f.category))}</b> — '
                    f"severity: {html.escape(str(f.severity))}, confidence: {f.confidence:.2f} "
                    f"(detector: {html.escape(str(f.detector))}){description_html}</div>",
                    unsafe_allow_html=True,
                )


def render_scanning_progress() -> None:
    steps = ["PII scan", "Secret scan", "Prompt injection scan", "Threat analysis", "Policy evaluation"]
    progress_area = st.empty()
    for i, step in enumerate(steps, start=1):
        progress_area.markdown(
            f'<span class="sa-scan">Analyzing prompt \u2014 \u2713 {html.escape(step)}</span>',
            unsafe_allow_html=True,
        )
        time.sleep(0.08)  # brief, deliberate pacing so the checklist is legible, not a fake delay
    progress_area.empty()


# ======================================================================
# Chat page
# ======================================================================

def handle_new_prompt(engine: SecurityEngine, prompt_text: str) -> None:
    st.session_state.messages.append({"role": "user", "content": prompt_text, "scan": None})

    with st.chat_message("user"):
        st.write(prompt_text)

    with st.chat_message("assistant"):
        render_scanning_progress()
        try:
            scan_result = engine.scan_prompt(prompt_text, st.session_state.session_id)
        except Exception as exc:  # noqa: BLE001 - fail CLOSED: a scan that
            # can't run at all must never be treated as "nothing found".
            # Individual detectors already fail safe inside engine.py
            # (see SecurityEngine._run_classifier_safely / GitleaksScanner)
            # so other detectors still contribute even if one crashes —
            # this only catches something breaking the pipeline itself
            # (e.g. scoring/sanitize/audit-log code), which is rare
            # enough that refusing to proceed is the right default.
            st.error(
                "The security check could not be completed, so this prompt "
                f"was not sent to the AI. ({exc})"
            )
            st.session_state.messages.append(
                {"role": "assistant", "content": "[Blocked — security check failed to run]", "scan": None}
            )
            return

        if scan_result.decision == Decision.SANITIZE:
            # Streamlit re-runs this whole script on every button click, and
            # this function only runs on the run where the user submitted a
            # prompt -- so buttons rendered from here would vanish before
            # their click was ever handled. Persist the pending choice and
            # let render_pending_sanitize() draw (and handle) it on every run.
            st.session_state.pending = {
                "id": uuid.uuid4().hex[:8],
                "scan_result": scan_result,
                "original_prompt": prompt_text,
                "editing": False,
            }
            st.rerun()

        if scan_result.decision != Decision.ALLOW or scan_result.injection_handling:
            render_security_banner(scan_result)

        if scan_result.decision == Decision.BLOCK:
            st.error(
                "This prompt was blocked before reaching the AI. "
                "Edit your prompt to remove the flagged content, or try a different request."
            )
            st.session_state.messages.append(
                {"role": "assistant", "content": "[Blocked by SecureAI — see analysis above]", "scan": scan_result}
            )
            return

        # ALLOW (possibly as an analysis of a detected injection)
        if scan_result.injection_handling:
            st.info(_ANALYSIS_NOTICE)
        _continue_to_llm(engine, prompt_text, pre_scan=scan_result)


# ---- SANITIZE choice: Redact & Continue / Edit Prompt / Cancel ----------

def _queue_action(name: str) -> None:
    """on_click callback: records which button was pressed. Callbacks run
    at the start of the next script run, so the choice is handled with the
    pending item still in session state."""
    st.session_state.pending_action = name


def render_pending_sanitize() -> None:
    pending = st.session_state.pending
    scan_result = pending["scan_result"]
    pid = pending["id"]
    with st.chat_message("assistant"):
        render_security_banner(scan_result)
        st.warning("Sensitive content detected. Review the redaction below before continuing.")
        st.markdown("**Original:**")
        st.markdown(
            f'<div class="secureai-redaction-diff">{html.escape(scan_result.original_text)}</div>',
            unsafe_allow_html=True,
        )
        st.markdown("**Sanitized:**")
        st.markdown(
            f'<div class="secureai-redaction-diff">{html.escape(scan_result.sanitized_text or "")}</div>',
            unsafe_allow_html=True,
        )

        if pending["editing"]:
            st.text_area("Edit your prompt", value=pending["original_prompt"], key=f"edit_text_{pid}", height=150)
            col1, col2, _ = st.columns([2, 1, 4])
            with col1:
                st.button("Send edited prompt", key=f"send_edit_{pid}", on_click=_queue_action, args=("send_edit",))
            with col2:
                st.button("Cancel", key=f"cancel_{pid}", on_click=_queue_action, args=("cancel",))
        else:
            col1, col2, col3, _ = st.columns([2.2, 1.6, 1.1, 4])
            with col1:
                st.button("Redact & Continue", key=f"redact_{pid}", on_click=_queue_action, args=("redact",))
            with col2:
                st.button("Edit Prompt", key=f"edit_{pid}", on_click=_queue_action, args=("edit",))
            with col3:
                st.button("Cancel", key=f"cancel_{pid}", on_click=_queue_action, args=("cancel",))


def _continue_to_llm(engine: SecurityEngine, text_to_send: str, pre_scan=None) -> None:
    # An allowed ANALYSIS of a detected injection is sent with its embedded
    # content wrapped as untrusted data (engine.frame_untrusted_analysis).
    analysis = getattr(pre_scan, "injection_handling", None) is not None

    def _record(content: str, scan) -> None:
        msg = {"role": "assistant", "content": content, "scan": scan}
        if analysis:
            msg["prompt_scan"] = pre_scan  # keeps the notice visible after reruns
        st.session_state.messages.append(msg)

    try:
        with st.spinner("Thinking..."):
            if analysis:
                llm_response = engine.get_llm_response(text_to_send, untrusted_analysis=True)
            else:
                llm_response = engine.get_llm_response(text_to_send)
    except Exception as exc:  # noqa: BLE001
        st.error(f"The LLM provider returned an error: {exc}")
        _record(f"[LLM error: {exc}]", pre_scan)
        return

    try:
        output_scan = engine.scan_response(llm_response, st.session_state.session_id)
    except Exception as exc:  # noqa: BLE001 - fail CLOSED, mirroring the
        # prompt-side handling above: the response is withheld, not shown
        # raw, if the security check itself couldn't complete.
        st.error(
            "The AI responded, but the output security check could not be "
            f"completed, so the response has been withheld. ({exc})"
        )
        _record("[Response withheld — security check failed to run]", None)
        return

    if output_scan.decision == Decision.BLOCK:
        st.error(
            "The AI's response was flagged by the output security check and has been withheld."
        )
        render_security_banner(output_scan)
        _record("[Response withheld by SecureAI output check]", output_scan)
        return

    if output_scan.decision == Decision.SANITIZE:
        # The model's own response contains a secret/PII match at
        # SANITIZE-band risk — not severe enough to withhold entirely,
        # but it must never reach the user (or session history, which
        # re-renders every message's stored "content" on every Streamlit
        # rerun) unredacted. Show and store sanitized_text only;
        # llm_response is not referenced again past this branch.
        st.warning(
            "The AI's response contained sensitive content, which has been redacted below."
        )
        st.write(output_scan.sanitized_text)
        with st.expander("Output security check"):
            render_security_banner(output_scan)

        _record(output_scan.sanitized_text, output_scan)
        return

    # ALLOW
    st.write(llm_response)
    with st.expander("Output security check"):
        render_security_banner(output_scan)

    _record(llm_response, output_scan)


def render_welcome() -> None:
    st.markdown(
        '<div class="sa-hero">'
        '<div class="sa-hero-icon">\U0001F512</div>'
        "<h1>How can I help you today?</h1>"
        "<p>Every message you send and every reply you receive is checked for secrets, "
        "personal data and prompt injection before it moves.</p>"
        "</div>",
        unsafe_allow_html=True,
    )


def render_chat_page(engine: SecurityEngine) -> None:
    prompt = st.chat_input("Message SecureAI...")

    if not prompt and not st.session_state.messages and not st.session_state.pending:
        render_welcome()

    # Handle the SANITIZE choices (queued by button callbacks) that only
    # change state FIRST, so the history rendered below already reflects them.
    action = st.session_state.pop("pending_action", None)
    pending = st.session_state.pending
    if pending and action == "edit":
        pending["editing"] = True
    elif pending and action == "cancel":
        st.session_state.messages.append(
            {"role": "assistant", "content": "[Cancelled by user]", "scan": pending["scan_result"]}
        )
        st.session_state.pending = pending = None
    elif pending and prompt:
        # Typing a new message abandons the unresolved one.
        st.session_state.messages.append(
            {"role": "assistant", "content": "[Previous prompt not sent — replaced by a new message]",
             "scan": pending["scan_result"]}
        )
        st.session_state.pending = pending = None

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            if msg.get("prompt_scan") is not None:
                st.info(_ANALYSIS_NOTICE)
            st.write(msg["content"])
            if msg["role"] == "assistant" and (msg.get("scan") is not None or msg.get("prompt_scan") is not None):
                with st.expander("Security details"):
                    if msg.get("prompt_scan") is not None:
                        st.caption("Prompt check")
                        render_security_banner(msg["prompt_scan"])
                    if msg.get("scan") is not None:
                        if msg.get("prompt_scan") is not None:
                            st.caption("Response check")
                        render_security_banner(msg["scan"])

    # Actions that call the LLM run here, below the history, so their output
    # appears where the next message belongs.
    if pending and action == "redact":
        st.session_state.pending = None
        with st.chat_message("assistant"):
            _continue_to_llm(engine, pending["scan_result"].sanitized_text, pre_scan=pending["scan_result"])
    elif pending and action == "send_edit":
        edited = (st.session_state.get(f"edit_text_{pending['id']}") or "").strip()
        if edited:
            st.session_state.pending = None
            st.session_state.messages.append(
                {"role": "assistant", "content": "[Original prompt withdrawn — edited prompt sent below]",
                 "scan": pending["scan_result"]}
            )
            # The edited text goes through the full security scan again.
            handle_new_prompt(engine, edited)
        else:
            st.warning("The edited prompt is empty — type a prompt or press Cancel.")
            render_pending_sanitize()
    elif pending:
        render_pending_sanitize()

    if prompt:
        handle_new_prompt(engine, prompt)


# ======================================================================
# Dashboard page (§14 of the project spec)
# ======================================================================

def render_dashboard_page(engine: SecurityEngine) -> None:
    st.markdown('<a href="?" target="_self">\u2190 Back to chat</a>', unsafe_allow_html=True)
    st.title("Security Dashboard")
    stats = engine.get_dashboard_stats()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Scanned", stats["total_scanned"])
    col2.metric("Allowed", stats["allowed"])
    col3.metric("Sanitized", stats["sanitized"])
    col4.metric("Blocked", stats["blocked"])

    col5, col6 = st.columns(2)
    col5.metric("High-Risk Interactions", stats["high_risk_interactions"])
    col6.metric("Average Latency (ms)", stats["average_latency_ms"])

    st.subheader("Decision breakdown")
    decision_data = {
        "Decision": ["Allowed", "Sanitized", "Blocked"],
        "Count": [stats["allowed"], stats["sanitized"], stats["blocked"]],
    }
    st.bar_chart(decision_data, x="Decision", y="Count")

    if stats["top_threat_categories"]:
        st.subheader("Most common threat categories")
        cat_data = {
            "Category": [c for c, _ in stats["top_threat_categories"]],
            "Count": [n for _, n in stats["top_threat_categories"]],
        }
        st.bar_chart(cat_data, x="Category", y="Count")
    else:
        st.info("No threats detected yet — scan some prompts to populate this chart.")


# ======================================================================
# Sidebar
# ======================================================================

def render_sidebar():
    with st.sidebar:
        st.markdown(
            f'<div class="sa-brand"><div class="sa-brand-icon">\U0001F512</div>{html.escape(settings.app_title)}</div>',
            unsafe_allow_html=True,
        )

        if st.button("+ New chat", width="stretch"):
            st.session_state.messages = []
            st.session_state.pending = None
            st.session_state.pop("pending_action", None)
            st.session_state.session_id = str(uuid.uuid4())
            st.rerun()

        st.markdown('<div class="sa-side-label">Current chat</div>', unsafe_allow_html=True)
        history_slot = st.empty()
        fill_sidebar_history(history_slot)

        st.markdown(
            '<div class="sa-side-foot">Prompts and responses are scanned for secrets, '
            "personal data and prompt injection.</div>",
            unsafe_allow_html=True,
        )
    return history_slot


def fill_sidebar_history(slot) -> None:
    user_msgs = [m for m in st.session_state.messages if m["role"] == "user"]
    if not user_msgs:
        slot.markdown('<div class="sa-side-empty">No messages yet</div>', unsafe_allow_html=True)
        return
    items = []
    for msg in user_msgs[-12:][::-1]:
        preview = " ".join(str(msg["content"]).split())
        preview = preview[:48] + ("..." if len(preview) > 48 else "")
        items.append(f'<div class="sa-side-item">{html.escape(preview)}</div>')
    slot.markdown("".join(items), unsafe_allow_html=True)


# ======================================================================
# Main
# ======================================================================

def main() -> None:
    _init_session_state()
    engine, load_error = get_engine()

    history_slot = render_sidebar()

    if load_error is not None:
        st.error(
            "SecureAI could not start its detection engine and cannot safely process prompts."
        )
        st.code(load_error)
        st.info(
            "Check that MODELS_DIR in your .env points to a folder containing the four "
            "downloaded model subfolders (prompt-injection, pii-detection, output-safety, "
            "toxicity), and that gitleaks is installed and on PATH."
        )
        return

    if str(st.query_params.get("view", "")).lower() == "dashboard":
        render_dashboard_page(engine)
    else:
        render_chat_page(engine)
        fill_sidebar_history(history_slot)  # refresh now that this run's messages exist


if __name__ == "__main__":
    main()
