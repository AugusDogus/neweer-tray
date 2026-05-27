use cosmic::app::{Core, Task};
use cosmic::iced::window::Id;
use cosmic::prelude::*;
use cosmic::widget;
use cosmic_applet_neewer::device;

const APP_ID: &str = "dev.augie.CosmicAppletNeewer";
const DEFAULT_ICON: &str = "dev.augie.CosmicAppletNeewer-symbolic";
const ACTIVE_ICON: &str = "dev.augie.CosmicAppletNeewer-active-symbolic";

#[derive(Default)]
pub struct AppModel {
    core: Core,
    assumed_on: bool,
    is_busy: bool,
    last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Message {
    ToggleLights,
    Toggled(Result<(), String>),
    Surface(cosmic::surface::Action),
}

impl cosmic::Application for AppModel {
    type Executor = cosmic::SingleThreadExecutor;
    type Flags = ();
    type Message = Message;

    const APP_ID: &'static str = APP_ID;

    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(core: Core, _flags: Self::Flags) -> (Self, Task<Self::Message>) {
        (
            Self {
                core,
                ..Default::default()
            },
            Task::none(),
        )
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let icon_name = if self.is_busy || self.last_error.is_some() || self.assumed_on {
            ACTIVE_ICON
        } else {
            DEFAULT_ICON
        };

        let tooltip_text = if self.is_busy {
            "Toggling lights...".to_owned()
        } else if let Some(err) = &self.last_error {
            err.clone()
        } else {
            "Toggle Neewer lights".to_owned()
        };

        let button = self
            .core
            .applet
            .icon_button(icon_name)
            .on_press(Message::ToggleLights);

        Element::from(
            self.core
                .applet
                .applet_tooltip(button, tooltip_text, false, Message::Surface, None),
        )
    }

    fn view_window(&self, _id: Id) -> Element<'_, Self::Message> {
        widget::text("Neewer Light Control").into()
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
        match message {
            Message::Surface(action) => {
                return cosmic::task::message(cosmic::Action::Cosmic(
                    cosmic::app::Action::Surface(action),
                ));
            }
            Message::ToggleLights => {
                if self.is_busy {
                    return Task::none();
                }

                self.is_busy = true;
                self.last_error = None;

                return Task::perform(
                    async { device::toggle_lights().map_err(|err| err.to_string()) },
                    |result| cosmic::Action::App(Message::Toggled(result)),
                );
            }
            Message::Toggled(result) => {
                self.is_busy = false;

                match result {
                    Ok(()) => {
                        self.assumed_on = !self.assumed_on;
                        self.last_error = None;
                    }
                    Err(err) => {
                        tracing::warn!("toggle failed: {err}");
                        self.last_error = Some(err);
                    }
                }
            }
        }

        Task::none()
    }

    fn style(&self) -> Option<cosmic::iced_core::theme::Style> {
        Some(cosmic::applet::style())
    }
}
