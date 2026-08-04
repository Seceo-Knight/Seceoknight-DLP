"""
Linux Print Job Monitor
Monitors CUPS print jobs via the CUPS API or log files
"""

import os
import time
import threading
import logging
import subprocess
import hashlib
from datetime import datetime

logger = logging.getLogger("dlp-agent.print")


class PrintMonitor:
    """Monitors CUPS print jobs on Linux systems"""

    def __init__(self, callback=None, poll_interval=5):
        self.callback = callback
        self.poll_interval = poll_interval
        self._running = False
        self._thread = None
        self._last_job_ids = set()

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("Print monitor started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Print monitor stopped")

    @property
    def is_running(self):
        return self._running

    def _monitor_loop(self):
        while self._running:
            try:
                self._check_print_jobs()
            except Exception as e:
                logger.error(f"Print monitor error: {e}")
            time.sleep(self.poll_interval)

    def _check_print_jobs(self):
        """Check for new print jobs using lpstat"""
        try:
            result = subprocess.run(
                ["lpstat", "-o"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return

            current_jobs = set()
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    job_id = parts[0]
                    current_jobs.add(job_id)

                    if job_id not in self._last_job_ids:
                        # New print job detected
                        owner = parts[1] if len(parts) > 1 else "unknown"
                        size = parts[2] if len(parts) > 2 else "unknown"

                        # Get job details
                        printer = job_id.split("-")[0] if "-" in job_id else "unknown"
                        document = self._get_job_document(job_id)
                        # Hash the physical spool file BEFORE returning to
                        # the callback -- the caller (agent.py) may cancel
                        # (delete) this same job right after handling this
                        # event if it classifies as Restricted, and CUPS
                        # purges completed/cancelled jobs' spool files
                        # promptly. Hashing here, ahead of that, means the
                        # highest-value case (a blocked print job) still
                        # gets a hash instead of silently missing one.
                        file_hash = self._hash_job_file(job_id)

                        event = {
                            "event_type": "print",
                            "printer": printer,
                            "document": document,
                            "owner": owner,
                            "size": size,
                            "job_id": job_id,
                            "file_hash": file_hash,
                            "timestamp": datetime.utcnow().isoformat(),
                        }

                        logger.info(f"Print job detected: {job_id} - {document}")

                        if self.callback:
                            self.callback(event)

            self._last_job_ids = current_jobs

        except FileNotFoundError:
            logger.debug("lpstat not available - CUPS not installed")
        except subprocess.TimeoutExpired:
            logger.warning("lpstat timed out")

    def _hash_job_file(self, job_id):
        """Best-effort SHA-256 of the spooled CUPS document data file.

        CUPS stores each job's data under /var/spool/cups/d<NNNNN>-<NNN>,
        where <NNNNN> is the job's numeric CUPS ID (the part after the last
        '-' in the "printer-NNN" identifier lpstat -o reports) zero-padded
        to 5 digits, and <NNN> is a per-file sequence number (usually 001
        for single-file jobs). Requires root to read -- the agent already
        runs as root for file-system monitoring. Returns None (not raises)
        if the spool file is missing/unreadable, which is common and
        expected once a job has finished printing or been purged.
        """
        try:
            numeric_id = job_id.rsplit("-", 1)[-1]
            if not numeric_id.isdigit():
                return None
            padded = numeric_id.zfill(5)
            spool_dir = "/var/spool/cups"
            if not os.path.isdir(spool_dir):
                return None
            candidates = sorted(
                f for f in os.listdir(spool_dir) if f.startswith(f"d{padded}-")
            )
            if not candidates:
                return None
            spool_path = os.path.join(spool_dir, candidates[0])
            sha256 = hashlib.sha256()
            with open(spool_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            return None
        except Exception as e:
            logger.debug(f"Print job hashing failed for {job_id}: {e}")
            return None

    def _get_job_document(self, job_id):
        """Get document name for a print job"""
        try:
            result = subprocess.run(
                ["lpstat", "-l", "-o", job_id],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "Title:" in line:
                    return line.split("Title:", 1)[1].strip()
                if "Document:" in line:
                    return line.split("Document:", 1)[1].strip()
        except Exception:
            pass
        return "Unknown Document"
