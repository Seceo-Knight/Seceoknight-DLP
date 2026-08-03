"""
Linux USB Storage Monitor

Detects USB mass-storage device connect/disconnect via udev (the same
kernel/userspace mechanism Linux itself uses for hotplug -- there is no
Linux equivalent of Windows' WM_DEVICECHANGE messages, udev monitoring is
the standard way to observe this). Extracts vendor_id/product_id/serial_number
from udev device properties, which read the same USB device descriptor
fields (idVendor/idProduct/iSerialNumber) Windows' USBSTOR driver reads --
so a device's identity here matches what the same physical device reports
when plugged into a Windows endpoint, and an allowlist built from Windows
history works unmodified for Linux.

Requires the `pyudev` package (and libudev, present on essentially every
modern Linux distribution already). Degrades to a no-op with a clear log
message if pyudev isn't installed, rather than crashing agent startup --
USB monitoring is additive, file monitoring must keep working regardless.
"""

import logging
import subprocess
import threading
import time
from typing import Callable, Dict, Optional

logger = logging.getLogger("dlp-agent.usb")

try:
    import pyudev
    PYUDEV_AVAILABLE = True
except ImportError:
    PYUDEV_AVAILABLE = False


class UsbMonitor:
    """Monitors USB mass-storage device connect/disconnect via udev."""

    def __init__(self, callback: Optional[Callable[[Dict], None]] = None):
        self.callback = callback
        self._running = False
        self._thread = None
        self._context = None
        self._monitor = None
        self._observer = None
        # device node (e.g. /dev/sdb) -> identity dict, so a later "remove"
        # event (which often has fewer populated properties than "add")
        # can still report the same serial/vendor/product it connected with.
        self._known_devices: Dict[str, Dict] = {}

    @property
    def is_available(self) -> bool:
        return PYUDEV_AVAILABLE

    def start(self):
        if self._running:
            return
        if not PYUDEV_AVAILABLE:
            logger.warning(
                "USB monitoring disabled: pyudev not installed. "
                "Install with: pip3 install pyudev"
            )
            return

        try:
            self._context = pyudev.Context()
            self._seed_already_connected_devices()

            self._monitor = pyudev.Monitor.from_netlink(self._context)
            self._monitor.filter_by(subsystem="block", device_type="disk")

            self._running = True
            self._observer = pyudev.MonitorObserver(
                self._monitor, callback=self._handle_udev_event, name="seceoknight-usb"
            )
            self._observer.start()
            logger.info("USB monitor started")
        except Exception as exc:
            logger.error(f"Failed to start USB monitor: {exc}")
            self._running = False

    def stop(self):
        self._running = False
        if self._observer:
            try:
                self._observer.stop()
            except Exception:
                pass
        logger.info("USB monitor stopped")

    def _seed_already_connected_devices(self):
        """Populate _known_devices with USB storage already attached at
        agent startup, so a disconnect later still resolves an identity
        (and so we don't miss reporting devices connected before the
        agent process existed)."""
        try:
            for device in self._context.list_devices(subsystem="block", DEVTYPE="disk"):
                if self._is_usb_storage(device):
                    identity = self._extract_identity(device)
                    if identity:
                        self._known_devices[device.device_node] = identity
        except Exception as exc:
            logger.debug(f"Failed to seed existing USB devices: {exc}")

    def _is_usb_storage(self, device) -> bool:
        try:
            return device.get("ID_BUS") == "usb" and device.get("DEVTYPE") == "disk"
        except Exception:
            return False

    def _extract_identity(self, device) -> Optional[Dict]:
        """Pull vendor/product/serial the same way Windows' USBSTOR
        registry path does -- from the USB device descriptor, just via
        udev's view of it instead of the registry."""
        try:
            vendor_id = device.get("ID_VENDOR_ID", "")
            product_id = device.get("ID_MODEL_ID", "")
            serial = device.get("ID_SERIAL_SHORT") or device.get("ID_SERIAL", "")
            vendor_name = device.get("ID_VENDOR", "Unknown")
            model_name = device.get("ID_MODEL", "Unknown Device")
            if not serial:
                # No stable identity to key an allowlist entry on -- skip
                # rather than report a device we can never re-recognize.
                return None
            return {
                "device_node": device.device_node,
                "vendor_id": vendor_id,
                "product_id": product_id,
                "serial_number": serial,
                "device_name": f"{vendor_name} {model_name}".strip(),
            }
        except Exception as exc:
            logger.debug(f"Failed to extract USB device identity: {exc}")
            return None

    def _handle_udev_event(self, device):
        try:
            if device.get("ID_BUS") != "usb":
                return  # Not USB -- e.g. internal SATA/NVMe disks also live under "block"

            action = device.action  # "add", "remove", "change", ...
            if action == "add":
                identity = self._extract_identity(device)
                if not identity:
                    return
                self._known_devices[device.device_node] = identity
                self._emit(identity, event="connect")
            elif action == "remove":
                identity = self._known_devices.pop(device.device_node, None)
                if not identity:
                    # Never saw the "add" (e.g. agent started after connect
                    # and seeding missed it) -- nothing to report against.
                    return
                self._emit(identity, event="disconnect")
        except Exception as exc:
            logger.error(f"Error handling udev event: {exc}")

    def _emit(self, identity: Dict, event: str):
        logger.info(f"USB {event}: {identity['device_name']} (serial={identity['serial_number']})")
        if self.callback:
            payload = dict(identity)
            payload["event"] = event
            self.callback(payload)

    def unmount_device(self, device_node: str) -> bool:
        """Best-effort unmount of all partitions on a USB block device, used
        as the enforcement action for devices not on the allowlist.

        This is a weaker guarantee than Windows' USBSTOR registry block
        (which prevents the driver from ever exposing the device as a
        drive at all) -- it only unmounts whatever's currently mounted,
        and a user could remount it manually afterward. A stronger
        block (udev rule to reject the device, or blacklisting usb-storage
        entirely) is a larger, more invasive change than an agent-side
        best-effort react-to-connect action can safely do; unmounting is
        the same class of mitigation CyberSentinel's Linux agent uses.
        """
        unmounted_any = False
        try:
            result = subprocess.run(
                ["lsblk", "-nrpo", "NAME,MOUNTPOINT", device_node],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split(None, 1)
                if len(parts) < 2 or not parts[1].strip():
                    continue
                part_device, mountpoint = parts[0], parts[1].strip()
                try:
                    r = subprocess.run(
                        ["umount", part_device], capture_output=True, text=True, timeout=10
                    )
                    if r.returncode == 0:
                        unmounted_any = True
                        logger.warning(f"Unmounted blocked USB device partition: {part_device} ({mountpoint})")
                    else:
                        logger.warning(f"Failed to unmount {part_device}: {r.stderr.strip()}")
                except Exception as exc:
                    logger.warning(f"Error unmounting {part_device}: {exc}")
        except FileNotFoundError:
            logger.debug("lsblk not available -- cannot enumerate partitions to unmount")
        except Exception as exc:
            logger.error(f"Error enumerating partitions for {device_node}: {exc}")
        return unmounted_any
