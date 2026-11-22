//! Small presentational building blocks shared by the views.

use gpui_kit::component::h_flex;
use gpui_kit::{Div, FontWeight, Hsla, IntoElement, ParentElement, SharedString, Styled, div, px};

use super::theme::{FONT_MONO, colors, text};
use crate::core::analysis::IndicatorKind;

/// A bordered panel on the surface color.
pub fn card() -> Div {
    div()
        .flex()
        .flex_col()
        .w_full()
        .gap_4()
        .p_5()
        .bg(colors::surface())
        .border_1()
        .border_color(colors::border())
        .rounded(px(12.0))
}

/// Quiet uppercase section heading.
pub fn section_label(title: &'static str, accent: Hsla) -> Div {
    h_flex()
        .gap_2()
        .items_center()
        .child(div().size(px(6.0)).rounded_full().bg(accent))
        .child(
            div()
                .text_size(px(12.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(colors::text_secondary())
                .child(title),
        )
}

/// Subtle horizontal divider.
pub fn divider() -> Div {
    div().h(px(1.0)).w_full().bg(colors::border())
}

/// A small pill with tinted background, e.g. `IPv4`, `HIGH · 78`.
pub fn pill(label: impl Into<SharedString>, color: Hsla) -> Div {
    div()
        .flex_none()
        .px_2()
        .py_0p5()
        .rounded(px(6.0))
        .bg(color.opacity(0.12))
        .border_1()
        .border_color(color.opacity(0.3))
        .text_color(color)
        .text_size(px(text::CAPTION))
        .font_weight(FontWeight::MEDIUM)
        .child(label.into())
}

/// The detected indicator type badge.
pub fn kind_pill(kind: IndicatorKind) -> Div {
    let color = if kind == IndicatorKind::Unknown {
        colors::text_muted()
    } else {
        colors::accent()
    };
    pill(kind.label(), color)
}

/// Monospace text for indicators and URLs.
pub fn mono(value: impl Into<SharedString>) -> Div {
    div().font_family(FONT_MONO).child(value.into())
}

/// Shortens long values like SHA-256 hashes for compact display.
pub fn ellipsize_middle(value: &str, max: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= max || max < 5 {
        return value.to_string();
    }
    let keep = (max - 1) / 2;
    let head: String = chars[..keep].iter().collect();
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{head}…{tail}")
}

/// Secondary muted caption text.
pub fn caption(value: impl Into<SharedString>) -> impl IntoElement {
    div()
        .text_size(px(text::CAPTION))
        .text_color(colors::text_muted())
        .child(value.into())
}

#[cfg(test)]
mod tests {
    use super::ellipsize_middle;

    #[test]
    fn ellipsizes_long_values() {
        assert_eq!(ellipsize_middle("short", 10), "short");
        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let out = ellipsize_middle(hash, 15);
        assert_eq!(out, "44d8861…8abb02f");
        assert_eq!(out.chars().count(), 15);
    }
}
