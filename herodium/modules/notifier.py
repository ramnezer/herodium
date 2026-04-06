import subprocess
import logging
import os
import pwd

class Notifier:
    def __init__(self, config, logger, scope="general"):
        self.config = config or {}
        self.logger = logger
        self.scope = scope
        self.enabled = self._resolve_enabled_state()

    def _resolve_enabled_state(self):
        """
        Resolve notification enablement by scope.

        general  -> notifications.enable (default: True)
        maltrail -> maltrail.desktop_notifications
                    fallback to notifications.enable
                    fallback to True
        """
        try:
            notifications_cfg = (self.config.get('notifications') or {})
            maltrail_cfg = (self.config.get('maltrail') or {})

            if self.scope == "maltrail":
                if 'desktop_notifications' in maltrail_cfg:
                    return bool(maltrail_cfg.get('desktop_notifications'))
                if 'enable' in notifications_cfg:
                    return bool(notifications_cfg.get('enable'))
                return True

            if 'enable' in notifications_cfg:
                return bool(notifications_cfg.get('enable'))

            return True

        except Exception:
            return True

    def send_notification(self, title, message, level='normal'):
        """
        Send a desktop notification to all active logged-in users.
        Uses 'env' inside sudo/runuser to bypass environment scrubbing.
        """
        if not self.enabled:
            return

        try:
            base_run_dir = '/run/user'
            if not os.path.exists(base_run_dir):
                return

            for entry in os.listdir(base_run_dir):
                if not entry.isdigit():
                    continue

                uid = int(entry)
                if uid < 1000:
                    continue

                try:
                    user_name = pwd.getpwuid(uid).pw_name
                    dbus_path = f"{base_run_dir}/{uid}/bus"

                    if not os.path.exists(dbus_path):
                        continue

                    self._dispatch(user_name, uid, dbus_path, title, message, level)

                except KeyError:
                    continue

        except Exception as e:
            self.logger.error(f"Notification loop error: {e}")

    def _dispatch(self, user, uid, dbus_path, title, message, level):
        """Dispatch a notification to a specific desktop session."""
        try:
            env_prefix = [
                '/usr/bin/env',
                f'DBUS_SESSION_BUS_ADDRESS=unix:path={dbus_path}',
                f'XDG_RUNTIME_DIR=/run/user/{uid}',
                'DISPLAY=:0',
            ]

            if os.path.exists('/usr/bin/sudo'):
                cmd = [
                    '/usr/bin/sudo',
                    '-u', user,
                ] + env_prefix + [
                    '/usr/bin/notify-send',
                    title,
                    message,
                    '-t', '10000',
                    '-u', level,
                    '-i', 'security-high'
                ]
            elif os.path.exists('/usr/sbin/runuser'):
                cmd = [
                    '/usr/sbin/runuser',
                    '-u', user,
                    '--',
                ] + env_prefix + [
                    '/usr/bin/notify-send',
                    title,
                    message,
                    '-t', '10000',
                    '-u', level,
                    '-i', 'security-high'
                ]
            else:
                self.logger.warning('Notification skipped: neither sudo nor runuser is available.')
                return

            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )

        except Exception as e:
            self.logger.error(f"Failed to notify user {user}: {e}")
