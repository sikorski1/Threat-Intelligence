//! Main window: input → analysis pipeline → report (or error).

use std::rc::Rc;
use std::time::{Duration, Instant};

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::scroll::ScrollableElement as _;
use gpui_kit::component::spinner::Spinner;
use gpui_kit::component::{Disableable as _, Icon, IconName, Sizable as _, TitleBar, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Animation, AnimationExt as _, AnyElement, AppContext as _, ClipboardItem, Context, Entity,
    FontWeight, InteractiveElement, IntoElement, ParentElement, Render, SharedString, Styled,
    Subscription, Task, Window, div, img, px, relative,
};

use super::components::{caption, card, ellipsize_middle, kind_pill, mono};
use super::report;
use super::theme::{FONT_MONO, FONT_UI, app_icon, colors, text};
use crate::core::analysis::{self, IndicatorKind, PipelineStep, Report};

#[derive(Clone, Copy, PartialEq, Eq)]
enum StepStatus {
    Pending,
    Running,
    Done,
    Failed,
}

struct StepView {
    step: PipelineStep,
    status: StepStatus,
    elapsed_ms: Option<u64>,
}

/// State of one analysis run while it is executing (and if it fails).
struct Run {
    indicator: String,
    kind: IndicatorKind,
    steps: Vec<StepView>,
    started: Instant,
}

impl Run {
    fn completed(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.status == StepStatus::Done)
            .count()
    }
}

enum Phase {
    Idle,
    Loading(Run),
    Done(Rc<Report>),
    Failed { run: Run, message: String },
}

pub(crate) struct Dashboard {
    input: Entity<InputState>,
    detected: Option<IndicatorKind>,
    validation: Option<SharedString>,
    phase: Phase,
    /// Incremented for each run; used to restart entry animations.
    run_id: usize,
    /// The running analysis task. Dropping it cancels the run.
    task: Option<Task<Option<()>>>,
    last_query: Option<String>,
    copied: bool,
    _subscriptions: Vec<Subscription>,
}

impl Dashboard {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("IP, domain, file hash, CVE ID, or package@version")
        });
        let subscription = cx.subscribe_in(&input, window, Self::on_input_event);
        input.update(cx, |state, cx| state.focus(window, cx));
        Self {
            input,
            detected: None,
            validation: None,
            phase: Phase::Idle,
            run_id: 0,
            task: None,
            last_query: None,
            copied: false,
            _subscriptions: vec![subscription],
        }
    }

    fn on_input_event(
        &mut self,
        state: &Entity<InputState>,
        event: &InputEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match event {
            InputEvent::Change => {
                let value = state.read(cx).value();
                let value = value.trim();
                self.detected = (!value.is_empty()).then(|| IndicatorKind::detect(value));
                self.validation = None;
                cx.notify();
            }
            InputEvent::PressEnter { .. } => self.analyze(window, cx),
            _ => {}
        }
    }

    fn is_loading(&self) -> bool {
        matches!(self.phase, Phase::Loading(_))
    }

    fn analyze(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.is_loading() {
            return;
        }
        let raw = self.input.read(cx).value().trim().to_string();
        self.start(raw, window, cx);
    }

    /// Validates the input and dispatches an analysis run.
    fn start(&mut self, raw: String, _window: &mut Window, cx: &mut Context<Self>) {
        if raw.is_empty() {
            self.validation = Some("Enter an indicator to analyze.".into());
            cx.notify();
            return;
        }
        let kind = IndicatorKind::detect(&raw);
        if kind == IndicatorKind::Unknown {
            self.validation = Some(
                "Unrecognized format. Enter an IP, domain, hash, CVE-YYYY-NNNN, or package@version."
                    .into(),
            );
            cx.notify();
            return;
        }

        let pipeline = analysis::pipeline(kind);
        self.validation = None;
        self.detected = Some(kind);
        self.copied = false;
        self.run_id += 1;
        self.last_query = Some(raw.clone());
        self.phase = Phase::Loading(Run {
            indicator: raw.clone(),
            kind,
            steps: pipeline
                .into_iter()
                .enumerate()
                .map(|(i, step)| StepView {
                    step,
                    status: match i {
                        0 => StepStatus::Done,
                        1 => StepStatus::Running,
                        _ => StepStatus::Pending,
                    },
                    elapsed_ms: (i == 0).then_some(0),
                })
                .collect(),
            started: Instant::now(),
        });

        self.task = Some(cx.spawn(async move |this, cx| {
            let result = analysis::run(raw, kind).await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(mut report) => {
                        if let Phase::Loading(run) = &this.phase {
                            report.elapsed_ms = run.started.elapsed().as_millis() as u64;
                        }
                        this.phase = Phase::Done(Rc::new(report));
                    }
                    Err(message) => {
                        if let Phase::Loading(mut run) =
                            std::mem::replace(&mut this.phase, Phase::Idle)
                        {
                            if let Some(step) = run.steps.get_mut(1) {
                                step.status = StepStatus::Failed;
                            }
                            this.phase = Phase::Failed { run, message };
                        }
                    }
                }
                cx.notify();
            })
            .ok()
        }));
        cx.notify();
    }

    fn cancel(&mut self, cx: &mut Context<Self>) {
        self.task = None;
        self.phase = Phase::Idle;
        cx.notify();
    }

    fn new_analysis(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.task = None;
        self.phase = Phase::Idle;
        self.detected = None;
        self.validation = None;
        self.copied = false;
        self.input.update(cx, |state, cx| {
            state.set_value("", window, cx);
            state.focus(window, cx);
        });
        cx.notify();
    }

    fn rerun(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(query) = self.last_query.clone() {
            self.start(query, window, cx);
        }
    }

    fn copy_report(&mut self, cx: &mut Context<Self>) {
        if let Phase::Done(report) = &self.phase {
            cx.write_to_clipboard(ClipboardItem::new_string(report.to_markdown()));
            self.copied = true;
            cx.notify();
        }
    }

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    fn render_title_bar(&self) -> impl IntoElement {
        TitleBar::new().child(
            h_flex()
                .gap_2()
                .items_center()
                .child(img(app_icon()).size(px(18.0)).rounded(px(4.0)))
                .child(
                    div()
                        .text_size(px(text::SMALL))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(colors::text())
                        .child("Threat Intelligence"),
                ),
        )
    }

    fn render_hero(&self) -> impl IntoElement {
        h_flex()
            .gap_4()
            .items_center()
            .pt_8()
            .child(
                div()
                    .p_1()
                    .rounded(px(14.0))
                    .bg(colors::surface())
                    .border_1()
                    .border_color(colors::border())
                    .child(img(app_icon()).size(px(44.0)).rounded(px(10.0))),
            )
            .child(
                v_flex()
                    .gap_0p5()
                    .child(
                        div()
                            .text_size(px(text::DISPLAY))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(colors::text())
                            .child("Threat Intelligence"),
                    )
                    .child(
                        div()
                            .text_size(px(text::BODY))
                            .text_color(colors::text_secondary())
                            .child("Inspect a suspicious IP, domain, file hash, CVE, or package."),
                    ),
            )
    }

    fn render_search(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let loading = self.is_loading();
        let suffix = self.detected.map(kind_pill);

        v_flex()
            .w_full()
            .gap_3()
            .child(
                h_flex()
                    .w_full()
                    .gap_2()
                    .child(
                        Input::new(&self.input)
                            .large()
                            .flex_1()
                            .cleanable(true)
                            .font_family(FONT_MONO)
                            .disabled(loading)
                            .prefix(
                                Icon::new(IconName::Search)
                                    .size_4()
                                    .text_color(colors::text_muted()),
                            )
                            .when_some(suffix, |input, pill| input.suffix(pill)),
                    )
                    .child(
                        Button::new("analyze")
                            .primary()
                            .large()
                            .label(if loading { "Analyzing…" } else { "Analyze" })
                            .loading(loading)
                            .disabled(loading)
                            .on_click(cx.listener(|this, _, window, cx| this.analyze(window, cx))),
                    ),
            )
            .when_some(self.validation.clone(), |el, message| {
                el.child(
                    h_flex()
                        .gap_1p5()
                        .text_size(px(text::CAPTION))
                        .text_color(colors::critical())
                        .child(Icon::new(IconName::CircleAlert).size_3p5())
                        .child(message),
                )
            })
    }

    fn render_steps(&self, run: &Run) -> impl IntoElement {
        v_flex().gap_1().children(run.steps.iter().map(|s| {
            let (icon, label_color): (AnyElement, _) = match s.status {
                StepStatus::Done => (
                    Icon::new(IconName::CircleCheck)
                        .size_4()
                        .text_color(colors::accent())
                        .into_any_element(),
                    colors::text_secondary(),
                ),
                StepStatus::Running => (
                    Spinner::new()
                        .small()
                        .color(colors::accent())
                        .into_any_element(),
                    colors::text(),
                ),
                StepStatus::Failed => (
                    Icon::new(IconName::CircleX)
                        .size_4()
                        .text_color(colors::critical())
                        .into_any_element(),
                    colors::critical(),
                ),
                StepStatus::Pending => (
                    div()
                        .size_3p5()
                        .rounded_full()
                        .border_1()
                        .border_color(colors::border_strong())
                        .into_any_element(),
                    colors::text_muted(),
                ),
            };
            let trailing: SharedString = match (s.status, s.elapsed_ms) {
                (StepStatus::Running, _) => "running…".into(),
                (StepStatus::Failed, _) => "failed".into(),
                (_, Some(ms)) => format!("{:.1} s", ms as f32 / 1000.0).into(),
                _ => "".into(),
            };
            h_flex()
                .w_full()
                .gap_3()
                .px_3()
                .py_1p5()
                .rounded(px(6.0))
                .when(s.status == StepStatus::Running, |el| el.bg(colors::raised()))
                .child(
                    div()
                        .size_4()
                        .flex_none()
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(icon),
                )
                .child(
                    h_flex()
                        .flex_1()
                        .gap_2()
                        .items_center()
                        .child(
                            div()
                                .text_size(px(text::SMALL))
                                .text_color(label_color)
                                .child(s.step.label),
                        )
                        .child(caption(format!("· {}", s.step.source))),
                )
                .child(
                    mono(trailing)
                        .text_size(px(text::CAPTION))
                        .text_color(match s.status {
                            StepStatus::Running => colors::accent(),
                            StepStatus::Failed => colors::critical(),
                            _ => colors::text_muted(),
                        }),
                )
        }))
    }

    fn render_loading(&self, run: &Run, cx: &mut Context<Self>) -> impl IntoElement {
        let fraction = run.completed() as f32 / run.steps.len().max(1) as f32;
        card()
            .gap_3()
            .child(
                h_flex()
                    .w_full()
                    .justify_between()
                    .items_center()
                    .child(
                        h_flex()
                            .gap_2p5()
                            .items_center()
                            .min_w_0()
                            .child(Spinner::new().small().color(colors::accent()))
                            .child(
                                mono(ellipsize_middle(&run.indicator, 44))
                                    .text_size(px(text::BODY))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(colors::text()),
                            )
                            .child(kind_pill(run.kind)),
                    )
                    .child(
                        Button::new("cancel")
                            .ghost()
                            .small()
                            .label("Cancel")
                            .on_click(cx.listener(|this, _, _, cx| this.cancel(cx))),
                    ),
            )
            .child(
                div()
                    .w_full()
                    .h(px(3.0))
                    .rounded_full()
                    .bg(colors::raised())
                    .child(
                        div()
                            .h_full()
                            .w(relative(fraction))
                            .rounded_full()
                            .bg(colors::accent()),
                    ),
            )
            .child(self.render_steps(run))
    }

    fn render_failed(&self, run: &Run, message: &str, cx: &mut Context<Self>) -> impl IntoElement {
        let failed_step = run
            .steps
            .iter()
            .find(|s| s.status == StepStatus::Failed)
            .map(|s| s.step.source)
            .unwrap_or("Analysis");

        card()
            .gap_3()
            .border_color(colors::critical().opacity(0.45))
            .child(
                h_flex()
                    .w_full()
                    .justify_between()
                    .items_center()
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(
                                Icon::new(IconName::TriangleAlert)
                                    .size_4()
                                    .text_color(colors::critical()),
                            )
                            .child(
                                div()
                                    .text_size(px(text::BODY))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(colors::text())
                                    .child(format!("{failed_step} failed")),
                            ),
                    )
                    .child(
                        mono(ellipsize_middle(&run.indicator, 32))
                            .text_size(px(text::CAPTION))
                            .text_color(colors::text_muted()),
                    ),
            )
            .child(
                div()
                    .text_size(px(text::SMALL))
                    .text_color(colors::text_secondary())
                    .child(message.to_string()),
            )
            .child(
                h_flex()
                    .gap_2()
                    .pt_1()
                    .child(
                        Button::new("retry")
                            .primary()
                            .small()
                            .icon(IconName::RefreshCw)
                            .label("Retry")
                            .on_click(cx.listener(|this, _, window, cx| this.rerun(window, cx))),
                    )
                    .child(
                        Button::new("new-after-error")
                            .ghost()
                            .small()
                            .label("Clear")
                            .on_click(
                                cx.listener(|this, _, window, cx| this.new_analysis(window, cx)),
                            ),
                    ),
            )
    }

    fn render_done(&self, report: &Report, cx: &mut Context<Self>) -> impl IntoElement {
        let actions = h_flex()
            .w_full()
            .justify_end()
            .gap_1()
            .child(
                Button::new("copy")
                    .ghost()
                    .small()
                    .icon(if self.copied { IconName::Check } else { IconName::Copy })
                    .label(if self.copied { "Copied" } else { "Copy markdown" })
                    .on_click(cx.listener(|this, _, _, cx| this.copy_report(cx))),
            )
            .child(
                Button::new("rerun")
                    .ghost()
                    .small()
                    .icon(IconName::RefreshCw)
                    .label("Re-run")
                    .on_click(cx.listener(|this, _, window, cx| this.rerun(window, cx))),
            )
            .child(
                Button::new("new-analysis")
                    .ghost()
                    .small()
                    .icon(IconName::Close)
                    .label("Clear")
                    .on_click(cx.listener(|this, _, window, cx| this.new_analysis(window, cx))),
            );

        div()
            .id(("report", self.run_id))
            .w_full()
            .child(report::render(report, actions))
            .with_animation(
                ("report-fade", self.run_id),
                Animation::new(Duration::from_millis(240)),
                |el, delta| el.opacity(delta).mt(px(8.0 * (1.0 - delta))),
            )
    }
}

impl Render for Dashboard {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let body: AnyElement = match &self.phase {
            Phase::Idle => div().into_any_element(),
            Phase::Loading(run) => self.render_loading(run, cx).into_any_element(),
            Phase::Done(report) => {
                let report = report.clone();
                self.render_done(&report, cx).into_any_element()
            }
            Phase::Failed { run, message } => self.render_failed(run, message, cx).into_any_element(),
        };

        v_flex()
            .size_full()
            .bg(colors::bg())
            .text_color(colors::text())
            .font_family(FONT_UI)
            .text_size(px(text::BODY))
            .child(self.render_title_bar())
            .child(
                div()
                    .id("main-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .child(
                        v_flex()
                            .w_full()
                            .max_w(px(840.0))
                            .mx_auto()
                            .px_8()
                            .py_6()
                            .gap_5()
                            .when(matches!(self.phase, Phase::Idle), |el| {
                                el.child(self.render_hero())
                            })
                            .child(self.render_search(cx))
                            .child(body),
                    ),
            )
    }
}
