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
            subtitle: 'Toggle lights',
            iconName: ICON_NAME,
        });

        this._defaultSubtitle = 'Toggle lights';
        this._busy = false;

        this.connect('clicked', () => this._toggleLights());
    }

    _toggleLights() {
        if (this._busy)
            return;

        this._busy = true;
        this.reactive = false;
        this.subtitle = 'Toggling...';

        const toggleCommand = `${GLib.get_home_dir()}/.local/bin/neewer-toggle`;

        let proc;
        try {
            proc = Gio.Subprocess.new(
                [toggleCommand],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE
            );
        } catch (error) {
            this._setError(error.message);
            return;
        }

        proc.communicate_utf8_async(null, null, (subprocess, result) => {
            try {
                const [, , stderr] = subprocess.communicate_utf8_finish(result);

                if (!subprocess.get_successful()) {
                    this._setError(stderr.trim() || 'Toggle failed');
                    return;
                }

                this.subtitle = this._defaultSubtitle;
            } catch (error) {
                this._setError(error.message);
                return;
            }

            this._busy = false;
            this.reactive = true;
        });
    }

    _setError(message) {
        this._busy = false;
        this.reactive = true;
        this.subtitle = message || 'Toggle failed';

        GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 5, () => {
            if (!this._busy)
                this.subtitle = this._defaultSubtitle;
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
