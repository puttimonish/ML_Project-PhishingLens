import streamlit as st
import subprocess
import sys
import os
import re
import html


# ============================================================
# PHISHLENS - FRONTEND
# ============================================================

st.set_page_config(
    page_title="PhishingLens",
    page_icon="🔎",
    layout="centered",
    initial_sidebar_state="collapsed",
)


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    /* -------------------- GLOBAL -------------------- */

    .stApp {
        background:
            radial-gradient(
                circle at 50% -20%,
                rgba(37, 99, 235, 0.16),
                transparent 38%
            ),
            #080b12;
        color: #f5f7fb;
    }

    .main .block-container {
        max-width: 920px;
        padding-top: 55px;
        padding-bottom: 70px;
    }

    header[data-testid="stHeader"] {
        background: transparent;
    }

    /* Hide Streamlit default menu/footer */

    #MainMenu {
        visibility: hidden;
    }

    footer {
        visibility: hidden;
    }

    /* -------------------- BRAND -------------------- */

    .brand {
        text-align: center;
        margin-bottom: 42px;
    }

    .brand-icon {
        font-size: 42px;
        margin-bottom: 8px;
    }

    .brand-title {
        font-size: 42px;
        font-weight: 800;
        letter-spacing: -1.8px;
        color: #ffffff;
        margin: 0;
    }

    .brand-title span {
        color: #38bdf8;
    }

    .brand-subtitle {
        margin-top: 9px;
        color: #8993a7;
        font-size: 14px;
        letter-spacing: 0.3px;
    }

    /* -------------------- HERO -------------------- */

    .hero {
        background:
            linear-gradient(
                145deg,
                rgba(18, 25, 40, 0.96),
                rgba(10, 14, 23, 0.96)
            );

        border: 1px solid rgba(148, 163, 184, 0.14);
        border-radius: 22px;
        padding: 30px 32px;
        margin-bottom: 24px;

        box-shadow:
            0 20px 60px rgba(0, 0, 0, 0.25);
    }

    .hero-title {
        font-size: 22px;
        font-weight: 750;
        margin-bottom: 8px;
        color: #f8fafc;
    }

    .hero-text {
        color: #94a3b8;
        font-size: 14px;
        line-height: 1.7;
        margin: 0;
    }

    /* -------------------- INPUT -------------------- */

    .input-label {
        color: #cbd5e1;
        font-size: 13px;
        font-weight: 650;
        margin-bottom: 7px;
    }

    div[data-testid="stTextInput"] input {
        background: #0d121d !important;
        color: #f8fafc !important;

        border: 1px solid #273247 !important;
        border-radius: 13px !important;

        padding: 14px 16px !important;

        font-size: 14px !important;
        height: 50px !important;
    }

    div[data-testid="stTextInput"] input:focus {
        border-color: #38bdf8 !important;
        box-shadow: 0 0 0 1px #38bdf8 !important;
    }

    div[data-testid="stTextInput"] input::placeholder {
        color: #64748b !important;
    }

    /* -------------------- BUTTON -------------------- */

    div.stButton > button {
        width: 100%;
        height: 48px;

        border-radius: 12px;

        background: linear-gradient(
            135deg,
            #0ea5e9,
            #2563eb
        );

        color: white;
        border: none;

        font-size: 14px;
        font-weight: 700;

        transition:
            transform 0.15s ease,
            box-shadow 0.15s ease;
    }

    div.stButton > button:hover {
        transform: translateY(-1px);

        box-shadow:
            0 10px 30px rgba(37, 99, 235, 0.28);
    }

    /* -------------------- QUICK TESTS -------------------- */

    .quick-title {
        color: #64748b;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        font-weight: 700;

        margin-top: 18px;
        margin-bottom: 9px;
    }

    /* -------------------- RESULT CARD -------------------- */

    .result-card {
        margin-top: 32px;

        border-radius: 20px;
        padding: 25px;

        border: 1px solid rgba(148, 163, 184, 0.13);

        background:
            linear-gradient(
                145deg,
                rgba(17, 24, 39, 0.98),
                rgba(10, 15, 24, 0.98)
            );

        box-shadow:
            0 20px 55px rgba(0, 0, 0, 0.22);
    }

    .result-header {
        display: flex;
        align-items: center;
        justify-content: space-between;

        margin-bottom: 20px;
    }

    .result-heading {
        font-size: 18px;
        font-weight: 750;
        color: #f8fafc;
    }

    .status {
        padding: 7px 12px;

        border-radius: 999px;

        font-size: 11px;
        font-weight: 800;

        letter-spacing: 0.5px;
    }

    .status-safe {
        color: #34d399;
        background: rgba(16, 185, 129, 0.12);
        border: 1px solid rgba(16, 185, 129, 0.2);
    }

    .status-danger {
        color: #fb7185;
        background: rgba(244, 63, 94, 0.12);
        border: 1px solid rgba(244, 63, 94, 0.2);
    }

    /* -------------------- URL DISPLAY -------------------- */

    .url-box {
        background: #080c14;

        border: 1px solid #1e293b;
        border-radius: 12px;

        padding: 13px 15px;

        color: #94a3b8;

        font-family: Consolas, monospace;
        font-size: 12px;

        word-break: break-all;

        margin-bottom: 22px;
    }

    /* -------------------- METRICS -------------------- */

    .metric-grid {
        display: grid;

        grid-template-columns:
            repeat(3, 1fr);

        gap: 12px;

        margin-bottom: 25px;
    }

    .metric {
        background: rgba(15, 23, 42, 0.75);

        border: 1px solid #1e293b;

        border-radius: 14px;

        padding: 16px;
    }

    .metric-label {
        color: #64748b;

        font-size: 10px;

        text-transform: uppercase;

        letter-spacing: 0.9px;

        margin-bottom: 7px;
    }

    .metric-value {
        color: #f8fafc;

        font-size: 23px;

        font-weight: 750;
    }

    /* -------------------- PROBABILITY BARS -------------------- */

    .section-title {
        color: #e2e8f0;

        font-size: 14px;

        font-weight: 700;

        margin-top: 23px;

        margin-bottom: 13px;
    }

    .probability-row {
        margin-bottom: 15px;
    }

    .probability-label {
        display: flex;

        justify-content: space-between;

        color: #94a3b8;

        font-size: 12px;

        margin-bottom: 6px;
    }

    .probability-track {
        width: 100%;

        height: 7px;

        background: #1e293b;

        border-radius: 999px;

        overflow: hidden;
    }

    .probability-fill-safe {
        height: 100%;

        background: #10b981;

        border-radius: 999px;
    }

    .probability-fill-danger {
        height: 100%;

        background: #f43f5e;

        border-radius: 999px;
    }

    /* -------------------- INDICATORS -------------------- */

    .indicator {
        padding: 12px 14px;

        border-radius: 11px;

        background: rgba(244, 63, 94, 0.07);

        border: 1px solid rgba(244, 63, 94, 0.13);

        color: #cbd5e1;

        font-size: 12px;

        margin-bottom: 8px;

        line-height: 1.5;
    }

    .indicator-safe {
        background: rgba(16, 185, 129, 0.07);

        border-color: rgba(16, 185, 129, 0.13);

        color: #a7f3d0;
    }

    /* -------------------- FOOTER -------------------- */

    .footer {
        margin-top: 55px;

        padding-top: 22px;

        border-top: 1px solid #1e293b;

        text-align: center;

        color: #475569;

        font-size: 11px;

        line-height: 1.7;
    }

    /* -------------------- MOBILE -------------------- */

    @media (max-width: 650px) {

        .main .block-container {
            padding-left: 18px;
            padding-right: 18px;
        }

        .brand-title {
            font-size: 32px;
        }

        .hero {
            padding: 23px;
        }

        .metric-grid {
            grid-template-columns: 1fr;
        }

    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# BRAND
# ============================================================

st.markdown(
    """
    <div class="brand">

        <div class="brand-icon">🔎</div>

        <div class="brand-title">
            PHISH<span>LENS</span>
        </div>

        <div class="brand-subtitle">
            Machine-Learning URL Security Analyzer
        </div>

    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HERO
# ============================================================

st.markdown(
    """
    <div class="hero">

        <div class="hero-title">
            Analyze a suspicious URL
        </div>

        <p class="hero-text">
            PhishingLens examines URL structure, suspicious patterns
            and machine-learning probabilities to estimate phishing risk.
        </p>

    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# INPUT
# ============================================================

st.markdown(
    '<div class="input-label">URL TO ANALYZE</div>',
    unsafe_allow_html=True,
)


url = st.text_input(
    "URL",
    placeholder="https://example.com/login",
    label_visibility="collapsed",
)


# ============================================================
# QUICK EXAMPLES
# ============================================================

st.markdown(
    '<div class="quick-title">Quick test</div>',
    unsafe_allow_html=True,
)

quick_col1, quick_col2 = st.columns(2)

with quick_col1:
    if st.button("✓ Google", use_container_width=True):
        url = "https://www.google.com"
        st.session_state["url"] = url

with quick_col2:
    if st.button("⚠ Test phishing URL", use_container_width=True):
        url = (
            "http://guiadebelezadejpa.com/"
            "Paypal_Virefication/"
            "5486ecddcd98d85e4a24ab714e60257d/"
        )
        st.session_state["url"] = url


# ============================================================
# SESSION STATE URL
# ============================================================

if "url" in st.session_state and not url:
    url = st.session_state["url"]


# ============================================================
# ANALYZE BUTTON
# ============================================================

analyze = st.button(
    "🔎  Analyze URL",
    use_container_width=True,
)


# ============================================================
# PARSER
# ============================================================

def parse_prediction_output(output):

    result = {
        "prediction": "UNKNOWN",
        "confidence": 0.0,
        "risk_score": 0,
        "risk_level": "UNKNOWN",
        "phishing_probability": 0.0,
        "legitimate_probability": 0.0,
        "indicators": [],
    }

    # ----------------------------
    # Prediction
    # ----------------------------

    match = re.search(
        r"Prediction\s*:\s*(LEGITIMATE|PHISHING)",
        output,
        re.IGNORECASE,
    )

    if match:
        result["prediction"] = match.group(1).upper()

    # ----------------------------
    # Confidence
    # ----------------------------

    match = re.search(
        r"Confidence\s*:\s*([\d.]+)%",
        output,
        re.IGNORECASE,
    )

    if match:
        result["confidence"] = float(match.group(1))

    # ----------------------------
    # Risk score
    # ----------------------------

    match = re.search(
        r"Risk Score\s*:\s*(\d+)\s*/\s*100",
        output,
        re.IGNORECASE,
    )

    if match:
        result["risk_score"] = int(match.group(1))

    # ----------------------------
    # Risk level
    # ----------------------------

    match = re.search(
        r"Risk Level\s*:\s*(LOW|MEDIUM|HIGH)",
        output,
        re.IGNORECASE,
    )

    if match:
        result["risk_level"] = match.group(1).upper()

    # ----------------------------
    # Phishing probability
    # ----------------------------

    match = re.search(
        r"Phishing Probability\s*:\s*([\d.]+)%",
        output,
        re.IGNORECASE,
    )

    if match:
        result["phishing_probability"] = float(match.group(1))

    # ----------------------------
    # Legitimate probability
    # ----------------------------

    match = re.search(
        r"Legitimate Probability\s*:\s*([\d.]+)%",
        output,
        re.IGNORECASE,
    )

    if match:
        result["legitimate_probability"] = float(match.group(1))

    # ----------------------------
    # Indicators
    # ----------------------------

    indicator_section = re.search(
        r"DETECTED INDICATORS(.*?)(?:={5,}|$)",
        output,
        re.IGNORECASE | re.DOTALL,
    )

    if indicator_section:

        lines = indicator_section.group(1).splitlines()

        for line in lines:

            line = line.strip()

            if not line:
                continue

            if line.startswith("[!]"):
                clean = line[3:].strip()
                result["indicators"].append(clean)

            elif line.startswith("[+]"):
                clean = line[3:].strip()
                result["indicators"].append(clean)

    return result


# ============================================================
# RUN PREDICTION
# ============================================================

if analyze:

    if not url.strip():

        st.warning("Please enter a URL first.")

    else:

        clean_url = url.strip()

        with st.spinner("Analyzing URL..."):

            try:

                command = [
                    sys.executable,
                    "-m",
                    "src.prediction.predictor",
                    clean_url,
                ]

                process = subprocess.run(
                    command,
                    cwd=PROJECT_ROOT,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                )

                output = process.stdout

                if process.returncode != 0:

                    st.error(
                        "The prediction engine returned an error."
                    )

                    if process.stderr:
                        st.code(process.stderr)

                    st.stop()

                result = parse_prediction_output(output)

            except subprocess.TimeoutExpired:

                st.error(
                    "The prediction engine took too long to respond."
                )

                st.stop()

            except Exception as error:

                st.error(
                    f"Unable to run the prediction engine: {error}"
                )

                st.stop()


        # ====================================================
        # RESULT
        # ====================================================

        prediction = result["prediction"]

        is_phishing = prediction == "PHISHING"

        if is_phishing:
            status_class = "status-danger"
            status_text = "PHISHING DETECTED"
        else:
            status_class = "status-safe"
            status_text = "LIKELY LEGITIMATE"


        safe_url = html.escape(clean_url)

        st.markdown(
            f"""
            <div class="result-card">

                <div class="result-header">

                    <div class="result-heading">
                        Analysis Result
                    </div>

                    <div class="status {status_class}">
                        {status_text}
                    </div>

                </div>

                <div class="url-box">
                    {safe_url}
                </div>

                <div class="metric-grid">

                    <div class="metric">

                        <div class="metric-label">
                            Confidence
                        </div>

                        <div class="metric-value">
                            {result["confidence"]:.2f}%
                        </div>

                    </div>

                    <div class="metric">

                        <div class="metric-label">
                            Risk Score
                        </div>

                        <div class="metric-value">
                            {result["risk_score"]}/100
                        </div>

                    </div>

                    <div class="metric">

                        <div class="metric-label">
                            Risk Level
                        </div>

                        <div class="metric-value">
                            {result["risk_level"]}
                        </div>

                    </div>

                </div>

                <div class="section-title">
                    Model Probabilities
                </div>

                <div class="probability-row">

                    <div class="probability-label">

                        <span>
                            Legitimate
                        </span>

                        <span>
                            {result["legitimate_probability"]:.2f}%
                        </span>

                    </div>

                    <div class="probability-track">

                        <div
                            class="probability-fill-safe"
                            style="width:
                            {result["legitimate_probability"]}%"
                        ></div>

                    </div>

                </div>

                <div class="probability-row">

                    <div class="probability-label">

                        <span>
                            Phishing
                        </span>

                        <span>
                            {result["phishing_probability"]:.2f}%
                        </span>

                    </div>

                    <div class="probability-track">

                        <div
                            class="probability-fill-danger"
                            style="width:
                            {result["phishing_probability"]}%"
                        ></div>

                    </div>

                </div>

            </div>
            """,
            unsafe_allow_html=True,
        )


        # ====================================================
        # INDICATORS
        # ====================================================

        indicators = result["indicators"]

        st.markdown(
            '<div class="section-title">Security Indicators</div>',
            unsafe_allow_html=True,
        )

        if indicators:

            for indicator in indicators:

                safe_indicator = html.escape(indicator)

                indicator_class = (
                    "indicator"
                    if is_phishing
                    else "indicator indicator-safe"
                )

                icon = "⚠" if is_phishing else "✓"

                st.markdown(
                    f"""
                    <div class="{indicator_class}">
                        {icon}&nbsp;&nbsp;{safe_indicator}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        else:

            st.markdown(
                """
                <div class="indicator indicator-safe">
                    ✓&nbsp;&nbsp;
                    No major suspicious indicators detected.
                </div>
                """,
                unsafe_allow_html=True,
            )


        # ====================================================
        # DISCLAIMER
        # ====================================================

        st.markdown(
            """
            <div class="footer">

                <b>PHISHLENS</b>
                &nbsp;•&nbsp;
                Machine-Learning URL Security Analyzer

                <br><br>

                Predictions are probabilistic and should not be treated
                as absolute proof of website safety.

            </div>
            """,
            unsafe_allow_html=True,
        )


# ============================================================
# DEFAULT FOOTER
# ============================================================

if not analyze:

    st.markdown(
        """
        <div class="footer">

            <b>PHISHLENS</b>
            &nbsp;•&nbsp;
            Machine-Learning URL Security Analyzer

            <br><br>

            Analyze URLs using the trained Random Forest model.

        </div>
        """,
        unsafe_allow_html=True,
    )