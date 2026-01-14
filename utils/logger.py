"""Central logging setup for ShadowRecon.

Creates output directories and configures console + file logging.
"""
import logging
import os
from typing import Optional


def setup_logging(level: str = "INFO", logfile: Optional[str] = None) -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    base_output = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")
    json_dir = os.path.join(base_output, "json")
    html_dir = os.path.join(base_output, "html")
    csv_dir = os.path.join(base_output, "csv")
    log_dir = os.path.join(base_output, "logs")

    for d in (json_dir, html_dir, csv_dir, log_dir):
        os.makedirs(d, exist_ok=True)

    if logfile is None:
        logfile = os.path.join(log_dir, "recon.log")

    logging.basicConfig(level=numeric, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # Add a file handler in addition to the root handler
    fh = logging.FileHandler(logfile)
    fh.setLevel(numeric)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.getLogger().addHandler(fh)


__all__ = ["setup_logging"]
