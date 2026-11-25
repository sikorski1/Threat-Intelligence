//! Final report presentation.

use gpui_kit::component::{Icon, IconName, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, Div, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    StatefulInteractiveElement, Styled, div, px, relative,
};

use super::components::{caption, card, divider, kind_pill, mono, pill, section_label};
use super::theme::{colors, text};
use crate::core::analysis::Report;
use crate::core::risk::RiskLevel;

/// Renders the report with a compact toolbar inside the header card.
pub fn render(report: &Report, actions: impl IntoElement) -> impl IntoElement {
    v_flex()
        .w_full()
        .gap_4()
        .child(verdict_and_summary_card(report, actions))
        .when(!report.findings.is_empty(), |el| el.child(findings_card(report)))
        .child(
            h_flex()
                .w_full()
                .gap_4()
                .items_start()
                .child(evidence_card(report))
                .child(hypotheses_card(report)),
        )
        .child(actions_and_sources_card(report))
}

fn verdict_and_summary_card(report: &Report, actions: impl IntoElement) -> Div {
    let risk_color = colors::risk(report.risk);

    card()
        .border_color(risk_color.opacity(0.45))
        .child(
            h_flex()
                .w_full()
                .items_start()
                .justify_between()
                .gap_6()
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .gap_1p5()
                        .child(
                            h_flex()
                                .gap_2()
                                .items_center()
                                .child(
                                    mono(report.indicator.clone())
                                        .text_size(px(text::TITLE))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(colors::text())
                                        .overflow_hidden()
                                        .text_ellipsis(),
                                )
                                .child(kind_pill(report.kind)),
                        )
                        .child(
                            div()
                                .text_size(px(text::BODY))
                                .text_color(colors::text_secondary())
                                .child(report.verdict.clone()),
                        ),
                )
                .child(
                    v_flex()
                        .flex_none()
                        .items_end()
                        .gap_1()
                        .child(
                            pill(format!("{} risk", report.risk.label()).to_uppercase(), risk_color)
                                .font_weight(FontWeight::BOLD),
                        )
                        .when_some(report.score, |el, score| {
                            el.child(
                                h_flex()
                                    .items_end()
                                    .gap_1()
                                    .child(
                                        mono(score.to_string())
                                            .text_size(px(36.0))
                                            .line_height(px(40.0))
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(risk_color),
                                    )
                                    .child(
                                        mono("/100")
                                            .pb_1()
                                            .text_size(px(text::SMALL))
                                            .text_color(colors::text_muted()),
                                    ),
                            )
                        })
                        .child(caption(format!(
                            "Confidence: {} · {:.1} s",
                            report.confidence.label(),
                            report.elapsed_ms as f32 / 1000.0
                        ))),
                ),
        )
        .child(risk_meter(report.risk))
        .child(divider())
        .child(
            div()
                .text_size(px(text::BODY))
                .line_height(relative(1.6))
                .text_color(colors::text())
                .child(report.summary.clone()),
        )
        .child(actions)
}

/// Four-segment Low → Critical scale harmonized in the app-icon cyan → worm-red ramp.
fn risk_meter(level: RiskLevel) -> Div {
    let current = level.rank();
    h_flex().w_full().gap_1().children(RiskLevel::SCALE.iter().map(|&segment| {
        let active = current.is_some_and(|c| segment.rank().is_some_and(|r| r <= c));
        let is_current = segment == level;
        let color = colors::risk(segment);
        v_flex()
            .flex_1()
            .gap_1()
            .child(
                div()
                    .h(px(6.0))
                    .rounded(px(3.0))
                    .bg(if active { color } else { colors::raised() }),
            )
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(if is_current { color } else { colors::text_muted() })
                    .when(is_current, |el| el.font_weight(FontWeight::SEMIBOLD))
                    .child(segment.label()),
            )
    }))
}

fn findings_card(report: &Report) -> Div {
    card()
        .gap_3()
        .child(section_label("Key findings", colors::high()))
        .child(v_flex().gap_2p5().children(report.findings.iter().map(|f| {
            let color = colors::risk(f.severity);
            h_flex()
                .w_full()
                .items_start()
                .gap_3()
                .child(div().mt(px(7.0)).size(px(7.0)).flex_none().rounded_full().bg(color))
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .gap_0p5()
                        .child(
                            div()
                                .text_size(px(text::BODY))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(colors::text())
                                .child(f.title.clone()),
                        )
                        .child(
                            div()
                                .text_size(px(text::SMALL))
                                .text_color(colors::text_secondary())
                                .child(f.detail.clone()),
                        ),
                )
                .child(
                    div()
                        .flex_none()
                        .text_size(px(text::CAPTION))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(color)
                        .child(f.severity.label()),
                )
        })))
}

/// One statement with a colored left accent bar.
fn ruled_item(color: Hsla, statement: String, footer: Option<AnyElement>) -> Div {
    v_flex()
        .gap_0p5()
        .pl_3()
        .border_l_2()
        .border_color(color)
        .child(
            div()
                .text_size(px(text::SMALL))
                .line_height(relative(1.5))
                .text_color(colors::text())
                .child(statement),
        )
        .children(footer)
}

fn evidence_card(report: &Report) -> Div {
    card()
        .flex_1()
        .min_w_0()
        .gap_3()
        .child(section_label("Verified evidence", colors::accent()))
        .when(report.evidence.is_empty(), |el| el.child(caption("None")))
        .child(v_flex().gap_3().children(report.evidence.iter().map(|e| {
            ruled_item(
                colors::accent(),
                e.statement.clone(),
                Some(
                    mono(e.source.clone())
                        .text_size(px(11.0))
                        .text_color(colors::text_muted())
                        .into_any_element(),
                ),
            )
        })))
}

fn hypotheses_card(report: &Report) -> Div {
    card()
        .flex_1()
        .min_w_0()
        .gap_3()
        .child(section_label("Hypotheses", colors::hypothesis()))
        .when(report.hypotheses.is_empty(), |el| el.child(caption("None")))
        .child(v_flex().gap_3().children(report.hypotheses.iter().map(|h| {
            ruled_item(colors::hypothesis(), h.clone(), None)
        })))
        .when(!report.gaps.is_empty(), |el| {
            el.child(divider()).child(
                v_flex()
                    .gap_2()
                    .child(section_label("Gaps", colors::medium()))
                    .children(report.gaps.iter().map(|g| {
                        h_flex()
                            .items_start()
                            .gap_2()
                            .text_size(px(text::SMALL))
                            .text_color(colors::text_secondary())
                            .child(div().flex_none().child("–"))
                            .child(div().flex_1().child(g.clone()))
                    })),
            )
        })
}

fn actions_and_sources_card(report: &Report) -> Div {
    card()
        .gap_3()
        .child(section_label("Recommended actions", colors::accent()))
        .child(v_flex().gap_2().children(report.recommendations.iter().enumerate().map(
            |(i, r)| {
                h_flex()
                    .items_start()
                    .gap_2p5()
                    .child(
                        mono(format!("{}.", i + 1))
                            .flex_none()
                            .w(px(18.0))
                            .text_size(px(text::SMALL))
                            .text_color(colors::accent()),
                    )
                    .child(
                        div()
                            .flex_1()
                            .text_size(px(text::SMALL))
                            .line_height(relative(1.5))
                            .text_color(colors::text())
                            .child(r.clone()),
                    )
            },
        )))
        .when(!report.sources.is_empty(), |el| {
            el.child(divider()).child(
                h_flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .child(caption("Sources:"))
                    .children(report.sources.iter().enumerate().map(|(i, s)| {
                        let url = s.url.clone();
                        h_flex()
                            .id(("source", i))
                            .gap_1()
                            .px_2()
                            .py_0p5()
                            .rounded(px(6.0))
                            .bg(colors::raised())
                            .border_1()
                            .border_color(colors::border())
                            .cursor_pointer()
                            .hover(|el| el.border_color(colors::accent()))
                            .on_click(move |_, _, cx| cx.open_url(&url))
                            .child(
                                div()
                                    .text_size(px(text::CAPTION))
                                    .text_color(colors::text_secondary())
                                    .child(s.name.clone()),
                            )
                            .child(
                                Icon::new(IconName::ExternalLink)
                                    .size_3()
                                    .text_color(colors::accent()),
                            )
                    })),
            )
        })
}
