mod ui;

use gpui_kit::{AppContext, Bounds, TitlebarOptions, WindowBounds, WindowOptions, px, size};

use ui::dashboard::Dashboard;

fn main() {
    gpui_kit::application().run(|cx| {
        gpui_kit::init(cx);

        let bounds = Bounds::centered(None, size(px(520.0), px(320.0)), cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            titlebar: Some(TitlebarOptions {
                title: Some("Threat Intelligence".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        gpui_kit::open_window(options, cx, |_, cx| cx.new(|_| Dashboard))
            .expect("Failed to open the Threat Intelligence window");
        cx.activate(true);
    });
}
