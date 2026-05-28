import Gio from 'gi://Gio';
import GObject from 'gi://GObject';
import GLib from 'gi://GLib';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as QuickSettings from 'resource:///org/gnome/shell/ui/quickSettings.js';

const ICON_NAME = 'dev.augie.CosmicAppletNeewer-symbolic';

const NeewerToggle = GObject.registerClass(
class NeewerToggle extends QuickSettings.QuickToggle {
    _init() {
        super._init({
            title: 'Neewer Lights',
            iconName: ICON_NAME,
            // `toggleMode: true` makes the underlying St.Button behave as a
            // proper toggle: clicking auto-flips `checked` and the panel
            // applies the on/off visual style. Without it, `checked` has no
            // visual effect.
            toggleMode: true,
        });

        this._busy = false;
        // The dongle exposes a stateless toggle command, so `checked` is an
        // optimistic local guess. Default to off on extension load.
        this.checked = false;
        this._refreshSubtitle();

        this.connect('clicked', () => this._handleClick());
    }

    _refreshSubtitle() {
        this.subtitle = this.checked ? 'On' : 'Off';
    }

    _handleClick() {
        // With `toggleMode: true`, the St.Button has already flipped `checked`
        // by the time this fires; `this.checked` is the desired new state.
        if (this._busy) {
            this.checked = !this.checked;
            return;
        }

        const previousChecked = !this.checked;
        this._busy = true;
        this.reactive = false;
        this.subtitle = 'Toggling…';

        const toggleCommand = `${GLib.get_home_dir()}/.local/bin/neewer-toggle`;

        let proc;
        try {
            proc = Gio.Subprocess.new(
                [toggleCommand],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE
            );
        } catch (error) {
            this.checked = previousChecked;
            this._setError(error.message);
            return;
        }

        proc.communicate_utf8_async(null, null, (subprocess, result) => {
            try {
                const [, , stderr] = subprocess.communicate_utf8_finish(result);

                if (!subprocess.get_successful()) {
                    this.checked = previousChecked;
                    this._setError(stderr.trim() || 'Toggle failed');
                    return;
                }
            } catch (error) {
                this.checked = previousChecked;
                this._setError(error.message);
                return;
            }

            this._busy = false;
            this.reactive = true;
            this._refreshSubtitle();
        });
    }

    _setError(message) {
        this._busy = false;
        this.reactive = true;
        this.subtitle = message || 'Toggle failed';

        GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 5, () => {
            if (!this._busy)
                this._refreshSubtitle();
            return GLib.SOURCE_REMOVE;
        });
    }
});

const NeewerIndicator = GObject.registerClass(
class NeewerIndicator extends QuickSettings.SystemIndicator {
    _init() {
        super._init();

        this.quickSettingsItems.push(new NeewerToggle());
    }

    destroy() {
        this.quickSettingsItems.forEach(item => item.destroy());
        super.destroy();
    }
});

export default class NeewerQuickToggleExtension extends Extension {
    enable() {
        this._indicator = new NeewerIndicator();
        Main.panel.statusArea.quickSettings.addExternalIndicator(this._indicator);
    }

    disable() {
        this._indicator?.destroy();
        this._indicator = null;
    }
}
