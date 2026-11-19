use gpui_kit::component::label::Label;
use gpui_kit::{Context, IntoElement, ParentElement, Render, Styled, Window, div};

pub(crate) struct Dashboard;

impl Render for Dashboard {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .size_full()
            .items_center()
            .justify_center()
            .text_xl()
            .child(Label::new("Hello, world!"))
    }
}
