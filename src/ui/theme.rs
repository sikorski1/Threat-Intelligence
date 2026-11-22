//! Visual identity: color palette derived from the app icon (electric cyan + worm crimson),
//! typography, and the gpui-component theme.

use std::borrow::Cow;
use std::sync::{Arc, LazyLock};

use gpui_kit::component::{Theme, ThemeMode};
use gpui_kit::{App, Hsla, Image, ImageFormat, px, rgb};

use crate::core::risk::RiskLevel;

/// Cached application icon embedded from `assets/app-icon.png`.
pub fn app_icon() -> Arc<Image> {
    static ICON: LazyLock<Arc<Image>> = LazyLock::new(|| {
        Arc::new(Image::from_bytes(
            ImageFormat::Png,
            include_bytes!("../../assets/app-icon.png").to_vec(),
        ))
    });
    ICON.clone()
}

/// UI typeface (bundled in `assets/fonts`).
pub const FONT_UI: &str = "Inter";
/// Typeface for indicators: IPs, hashes, CVE IDs, URLs.
pub const FONT_MONO: &str = "JetBrains Mono";

/// Type scale in pixels.
pub mod text {
    pub const DISPLAY: f32 = 24.0;
    pub const TITLE: f32 = 18.0;
    pub const BODY: f32 = 14.0;
    pub const SMALL: f32 = 13.0;
    pub const CAPTION: f32 = 12.0;
}

macro_rules! palette {
    ($($(#[$doc:meta])* $name:ident = $hex:literal),* $(,)?) => {
        $( $(#[$doc])* pub fn $name() -> Hsla { rgb($hex).into() } )*
    };
}

/// Dark obsidian palette anchored on the app icon's cyan (`#2FDEF1`) and worm-red (`#ED3154`).
pub mod colors {
    use super::*;

    palette! {
        /// Window background (matches the icon backdrop).
        bg = 0x090E14,
        /// Cards and panels.
        surface = 0x101720,
        /// Raised elements: inputs, chips, active rows.
        raised = 0x182230,
        border = 0x233042,
        border_strong = 0x314259,
        text = 0xE6EDF3,
        text_secondary = 0x8B98A9,
        text_muted = 0x5C6B7E,
        /// Primary analytical accent (app-icon electric cyan).
        accent = 0x2FDEF1,
        accent_hover = 0x67EAFA,
        accent_active = 0x10B8CC,
        /// Text drawn on top of the cyan accent.
        accent_fg = 0x041F26,
        /// Primary threat accent (app-icon crimson worm red).
        critical = 0xFD3A5D,
        high = 0xED3154,
        medium = 0xF4728A,
        low = 0x2FDEF1,
        unknown = 0x64748B,
        /// Unverified hypotheses (quiet cool slate, secondary to cyan evidence).
        hypothesis = 0x7A8B9E,
    }

    pub fn risk(level: RiskLevel) -> Hsla {
        match level {
            RiskLevel::Critical => critical(),
            RiskLevel::High => high(),
            RiskLevel::Medium => medium(),
            RiskLevel::Low => low(),
            RiskLevel::Unknown => unknown(),
        }
    }
}

/// Registers the bundled Inter and JetBrains Mono font files.
pub fn load_fonts(cx: &mut App) {
    let fonts: Vec<Cow<'static, [u8]>> = vec![
        Cow::Borrowed(include_bytes!("../../assets/fonts/Inter-400.ttf")),
        Cow::Borrowed(include_bytes!("../../assets/fonts/Inter-500.ttf")),
        Cow::Borrowed(include_bytes!("../../assets/fonts/Inter-600.ttf")),
        Cow::Borrowed(include_bytes!("../../assets/fonts/Inter-700.ttf")),
        Cow::Borrowed(include_bytes!("../../assets/fonts/JetBrainsMono-400.ttf")),
        Cow::Borrowed(include_bytes!("../../assets/fonts/JetBrainsMono-500.ttf")),
        Cow::Borrowed(include_bytes!("../../assets/fonts/JetBrainsMono-600.ttf")),
    ];
    if let Err(err) = cx.text_system().add_fonts(fonts) {
        eprintln!("failed to load bundled fonts: {err:#}");
    }
}

/// Switches gpui-component to dark mode and applies our palette and fonts.
pub fn apply(cx: &mut App) {
    use colors::*;

    Theme::change(ThemeMode::Dark, None, cx);
    Theme::update(cx, |theme| {
        theme.font_family = FONT_UI.into();
        theme.font_size = px(text::BODY);
        theme.mono_font_family = FONT_MONO.into();
        theme.mono_font_size = px(text::SMALL);
        theme.radius = px(8.0);
        theme.radius_lg = px(12.0);
        theme.shadow = false;

        let c = &mut theme.colors;
        c.background = bg();
        c.foreground = text();
        c.border = border();
        c.input = border_strong();
        c.ring = accent();
        c.caret = accent();
        c.selection = accent().opacity(0.28);

        c.primary = accent();
        c.primary_hover = accent_hover();
        c.primary_active = accent_active();
        c.primary_foreground = accent_fg();
        c.button_primary = accent();
        c.button_primary_hover = accent_hover();
        c.button_primary_active = accent_active();
        c.button_primary_foreground = accent_fg();

        c.secondary = raised();
        c.secondary_hover = border();
        c.secondary_active = border_strong();
        c.secondary_foreground = text();
        c.button = raised();
        c.button_hover = border();
        c.button_active = border_strong();
        c.button_foreground = text();

        c.muted = raised();
        c.muted_foreground = text_muted();
        c.accent = raised();
        c.accent_foreground = text();
        c.popover = surface();
        c.popover_foreground = text();
        c.skeleton = raised();
        c.progress_bar = accent();

        c.danger = critical();
        c.warning = medium();
        c.success = accent();
        c.info = accent();
        c.link = accent();
        c.link_hover = accent_hover();
        c.link_active = accent_active();

        c.title_bar = bg();
        c.title_bar_border = border();
        c.window_border = border();
        c.scrollbar_thumb = border_strong();
        c.scrollbar_thumb_hover = text_muted();
    });
}
