use cosmic_applet_neewer::device;
use ksni::blocking::TrayMethods;
use ksni::menu::StandardItem;

const APP_ID: &str = "dev.augie.NeewerTray";
const DEFAULT_ICON: &str = "dev.augie.CosmicAppletNeewer-symbolic";
const ACTIVE_ICON: &str = "dev.augie.CosmicAppletNeewer-active-symbolic";

struct NeewerTray {
    assumed_on: bool,
    is_busy: bool,
    last_error: Option<String>,
    icon_theme_path: String,
}

impl NeewerTray {
    fn toggle_lights(&mut self) {
        if self.is_busy {
            return;
        }

        self.is_busy = true;
        self.last_error = None;

        match device::toggle_lights() {
            Ok(()) => {
                self.assumed_on = !self.assumed_on;
            }
            Err(err) => {
                let err = err.to_string();
                tracing::warn!("toggle failed: {err}");
                self.last_error = Some(err);
            }
        }

        self.is_busy = false;
    }

    fn current_icon_name(&self) -> String {
        if self.is_busy || self.last_error.is_some() || self.assumed_on {
            ACTIVE_ICON.into()
        } else {
            DEFAULT_ICON.into()
        }
    }

    fn tooltip_description(&self) -> String {
        if self.is_busy {
            "Toggling lights...".into()
        } else if let Some(err) = &self.last_error {
            err.clone()
        } else {
            "Left-click to toggle Neewer lights".into()
        }
    }
}

impl ksni::Tray for NeewerTray {
    fn id(&self) -> String {
        APP_ID.into()
    }

    fn title(&self) -> String {
        "Neewer Tray".into()
    }

    fn status(&self) -> ksni::Status {
        if self.last_error.is_some() {
            ksni::Status::NeedsAttention
        } else {
            ksni::Status::Active
        }
    }

    fn icon_theme_path(&self) -> String {
        self.icon_theme_path.clone()
    }

    fn icon_name(&self) -> String {
        self.current_icon_name()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: self.current_icon_name(),
            icon_pixmap: Vec::new(),
            title: "Neewer Tray".into(),
            description: self.tooltip_description(),
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.toggle_lights();
    }

    fn secondary_activate(&mut self, _x: i32, _y: i32) {
        self.toggle_lights();
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        let mut menu = Vec::new();

        menu.push(
            StandardItem {
                label: if self.is_busy {
                    "Toggling lights...".into()
                } else {
                    "Toggle lights".into()
                },
                enabled: !self.is_busy,
                activate: Box::new(|tray: &mut Self| tray.toggle_lights()),
                ..Default::default()
            }
            .into(),
        );

        if let Some(err) = &self.last_error {
            menu.push(
                StandardItem {
                    label: err.clone(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
            );
        }

        menu.push(ksni::MenuItem::Separator);
        menu.push(
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        );

        menu
    }

    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        tracing::warn!("status notifier watcher offline: {reason:?}");
        true
    }
}

fn icon_theme_path() -> String {
    format!("{}/data/icons", env!("CARGO_MANIFEST_DIR"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let tray = NeewerTray {
        assumed_on: false,
        is_busy: false,
        last_error: None,
        icon_theme_path: icon_theme_path(),
    };

    let _handle = tray.spawn().map_err(|err| {
        std::io::Error::other(format!(
            "{err}. On GNOME you need the AppIndicator/KStatusNotifierItem shell extension enabled for the tray icon to appear."
        ))
    })?;

    loop {
        std::thread::park();
    }
}
