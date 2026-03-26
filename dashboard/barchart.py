import plotly.graph_objects as go


def extract_signal_data(rule_output):
    breakdown = rule_output["per_signal_breakdown"]

    signals = []
    scores = []
    colors = []

    for name, data in breakdown.items():
        score = data["score"]

        signals.append(name.replace("_", " ").title())
        scores.append(score)

        if score >= 0.6:
            colors.append("#dc3545")  # high
        elif score >= 0.3:
            colors.append("#ffc107")  # medium
        else:
            colors.append("#28a745")  # low

    return signals, scores, colors


def create_bar_chart(rule_output):
    signals, scores, colors = extract_signal_data(rule_output)

    fig = go.Figure(go.Bar(
        x=scores,
        y=signals,
        orientation='h',
        marker=dict(color=colors),
        text=[f"{s:.2f}" for s in scores],
        textposition='auto'
    ))

    fig.update_layout(
        title="Social Engineering Signal Strength",
        xaxis=dict(title="Strength (0–1)", range=[0, 1]),
        yaxis=dict(title="Signals"),
        margin=dict(l=40, r=20, t=40, b=20),
        height=350
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