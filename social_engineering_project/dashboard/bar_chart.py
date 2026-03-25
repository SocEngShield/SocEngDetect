import plotly.graph_objects as go


# Signal name display mapping
SIGNAL_DISPLAY_NAMES = {
    "fear_threat": "Fear/Threat",
    "impersonation": "Impersonation",
    "authority": "Authority",
    "urgency": "Urgency",
    "reward_lure": "Reward/Lure",
}


def _format_signal_name(name):
    """Convert internal signal name to display format."""
    return SIGNAL_DISPLAY_NAMES.get(name, name.replace("_", " ").title())


def extract_signal_data(rule_output):
    breakdown = rule_output["per_signal_breakdown"]

    signals = []
    scores = []
    colors = []
    ml_boosted = []

    for name, data in breakdown.items():
        score = data["score"]

        signals.append(_format_signal_name(name))
        scores.append(score)
        ml_boosted.append(data.get("ml_boosted", False))

        if score >= 0.6:
            colors.append("#ff4d4f")
        elif score >= 0.3:
            colors.append("#ffa940")
        else:
            colors.append("#52c41a")

    return signals, scores, colors, ml_boosted


def create_bar_chart(rule_output):
    signals, scores, colors, ml_boosted = extract_signal_data(rule_output)

    # Add ML indicator to labels for boosted signals
    labels = []
    for i, (signal, score, boosted) in enumerate(zip(signals, scores, ml_boosted)):
        if boosted and score > 0:
            labels.append(f"{score:.2f} [ML]")
        else:
            labels.append(f"{score:.2f}")

    fig = go.Figure(go.Bar(
        x=scores,
        y=signals,
        orientation='h',
        marker=dict(color=colors),
        text=labels,
        textposition='inside'
    ))

    fig.update_layout(
        paper_bgcolor="#0e1117",
        plot_bgcolor="#0e1117",

        xaxis=dict(
            title="Strength (0–1)",
            range=[0, 1],
            showgrid=True,
            gridcolor="#2a2a2a",
            zeroline=True,
            zerolinecolor="#888"
        ),

        yaxis=dict(
            title="Signals",
            showgrid=False
        ),

        margin=dict(l=60, r=40, t=30, b=40),
        height=380,

        shapes=[
            dict(
                type="rect",
                x0=0, y0=-0.5,
                x1=1, y1=len(signals)-0.5,
                line=dict(color="#444", width=1),
                fillcolor="rgba(0,0,0,0)"
            )
        ]
    )

    return fig


def get_top_signals(rule_output, top_n=2):
    breakdown = rule_output["per_signal_breakdown"]

    sorted_signals = sorted(
        breakdown.items(),
        key=lambda x: x[1]["score"],
        reverse=True
    )

    return [
        (name, data["score"])
        for name, data in sorted_signals[:top_n]
        if data["score"] > 0
    ]