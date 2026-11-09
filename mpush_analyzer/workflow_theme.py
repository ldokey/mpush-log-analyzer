"""Shared Streamlit skin derived from the actual v4.4 Stitch design tokens."""
from pathlib import Path
import streamlit as st


def apply_theme():
    tokens=(Path(__file__).with_name('diagnostics_web')/'workflow-tokens.css').read_text()
    css='''
    [data-testid="stAppViewContainer"]{background:var(--bg-canvas);color:var(--text-main)}
    .block-container{max-width:1500px;padding-top:2rem;padding-bottom:2rem}
    h1{font-size:1.45rem!important;margin:0!important;padding-bottom:.1rem!important}
    h2,h3{color:var(--text-main);letter-spacing:-.02em}
    [data-testid="stRadio"] [role="radiogroup"]{gap:.5rem;flex-wrap:wrap}
    [data-testid="stRadio"] [role="radiogroup"]>label{padding:.55rem .9rem;border:1px solid var(--border-light);border-radius:var(--radius-md);background:var(--bg-surface)}
    [data-testid="stRadio"] [role="radiogroup"]>label:has(input:checked){border-color:var(--brand-indigo-border);background:var(--brand-indigo-light)}
    [data-testid="stExpander"]{background:var(--bg-surface);border-radius:var(--radius-md);border-color:var(--border-light)}
    [data-testid="stFileUploader"]{background:var(--bg-surface);border:1px dashed var(--brand-indigo-border);border-radius:var(--radius-lg);padding:1rem}
    [data-testid="stBaseButton-primary"],[data-testid="stFormSubmitButton"] button[kind="primaryFormSubmit"]{background:var(--brand-indigo);border-color:var(--brand-indigo)}
    [data-testid="stDataFrame"]{border-radius:var(--radius-md);border:1px solid var(--border-light)}
    .intake-guide{border:1px solid var(--border-light);border-radius:var(--radius-lg);background:var(--bg-surface);padding:1.1rem 1.2rem;font-size:.85rem;line-height:1.75}
    .intake-guide strong{color:var(--brand-indigo)}.intake-guide p{margin:.6rem 0}
    '''
    st.markdown('<style>'+tokens+css+'</style>',unsafe_allow_html=True)
