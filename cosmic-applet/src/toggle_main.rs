use cosmic_applet_neewer::device;

fn main() -> std::process::ExitCode {
    match device::toggle_lights() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            std::process::ExitCode::FAILURE
        }
    }
}
