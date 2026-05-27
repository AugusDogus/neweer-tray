use hidapi::{HidApi, HidError};
use std::fmt;

const NEEWER_VID: u16 = 0x0581;
const NEEWER_PID: u16 = 0x011D;

const PACKET_HEADER: [u8; 7] = [0xba, 0x70, 0x24, 0x00, 0x00, 0x00, 0x00];
const ON_OFF_COMMAND: [u8; 6] = [0x77, 0x58, 0x01, 0x85, 0x01, 0x56];

#[derive(Debug, Clone)]
pub enum ToggleError {
    Hid(String),
    DongleNotFound,
    CommandRejected,
}

impl fmt::Display for ToggleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hid(err) => write!(f, "hid error: {err}"),
            Self::DongleNotFound => f.write_str("Neewer dongle not connected"),
            Self::CommandRejected => f.write_str("device rejected all known packet formats"),
        }
    }
}

impl From<HidError> for ToggleError {
    fn from(value: HidError) -> Self {
        Self::Hid(value.to_string())
    }
}

fn build_packet_64() -> [u8; 64] {
    let mut packet = [0u8; 64];
    packet[..PACKET_HEADER.len()].copy_from_slice(&PACKET_HEADER);
    packet[PACKET_HEADER.len()..PACKET_HEADER.len() + ON_OFF_COMMAND.len()]
        .copy_from_slice(&ON_OFF_COMMAND);
    packet
}

fn build_packet_32() -> [u8; 32] {
    let mut packet = [0u8; 32];
    packet[..ON_OFF_COMMAND.len()].copy_from_slice(&ON_OFF_COMMAND);
    packet
}

fn build_hid_write_packet_32() -> [u8; 33] {
    let mut packet = [0u8; 33];
    packet[1..].copy_from_slice(&build_packet_32());
    packet
}

// Empirical: in the captured Windows protocol session, the on/off command
// appears ~19 times per logical click (see scripts/analyze_protocol.py).
// Sending a single HID write does not reliably reach the lights; we need
// to retransmit. The lights dedupe identical packets within a short window
// so this still produces exactly one logical toggle per click.
const TOGGLE_REPEATS: usize = 20;
const TOGGLE_REPEAT_DELAY_MS: u64 = 15;

fn toggle_device(api: &HidApi, device_info: &hidapi::DeviceInfo) -> Result<bool, ToggleError> {
    let device = device_info.open_device(api)?;

    // The dongle's RF link is unreliable for a single HID write: lights
    // frequently miss isolated packets, so a lone toggle gets dropped and
    // the lights don't change state. The original Neewer Windows app
    // retransmits the same on/off command ~19 times per logical click
    // (see scripts/analyze_protocol.py); the lights dedupe identical
    // packets within a short window so this still results in exactly
    // one toggle per invocation.
    let packet_64 = build_packet_64();
    let mut succeeded = 0usize;
    for i in 0..TOGGLE_REPEATS {
        if let Ok(n) = device.write(&packet_64) {
            if n == packet_64.len() {
                succeeded += 1;
            }
        }
        if i + 1 < TOGGLE_REPEATS {
            std::thread::sleep(std::time::Duration::from_millis(TOGGLE_REPEAT_DELAY_MS));
        }
    }
    if succeeded > 0 {
        return Ok(true);
    }

    let packet_32 = build_hid_write_packet_32();
    if device.write(&packet_32).is_ok() {
        return Ok(true);
    }
    if device.send_feature_report(&packet_32).is_ok() {
        return Ok(true);
    }

    Ok(false)
}

pub fn toggle_lights() -> Result<(), ToggleError> {
    let api = HidApi::new()?;
    let mut saw_device = false;
    let mut last_error: Option<ToggleError> = None;

    for device_info in api
        .device_list()
        .filter(|device| device.vendor_id() == NEEWER_VID && device.product_id() == NEEWER_PID)
    {
        saw_device = true;

        match toggle_device(&api, device_info) {
            Ok(true) => return Ok(()),
            Ok(false) => continue,
            Err(err) => {
                tracing::warn!("failed to talk to candidate Neewer device: {err}");
                last_error = Some(err);
            }
        }
    }

    if !saw_device {
        return Err(ToggleError::DongleNotFound);
    }

    if let Some(err) = last_error {
        return Err(err);
    }

    Err(ToggleError::CommandRejected)
}
