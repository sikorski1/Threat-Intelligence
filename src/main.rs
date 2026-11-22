mod core;
mod ui;

use gpui_kit::component::TitleBar;
use gpui_kit::{AppContext, Bounds, WindowBounds, WindowOptions, px, size};

use ui::dashboard::Dashboard;

fn main() {
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(|cx| {
            gpui_kit::init(cx);
            ui::theme::load_fonts(cx);
            ui::theme::apply(cx);

            let bounds = Bounds::centered(None, size(px(1000.0), px(860.0)), cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(720.0), px(560.0))),
                ..TitleBar::window_options()
            };

            gpui_kit::open_window(options, cx, |window, cx| {
                cx.new(|cx| Dashboard::new(window, cx))
            })
            .expect("Failed to open the Threat Intelligence window");
            cx.activate(true);
        });
}
