"""State faults applied to an agent's store or state files."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .catalog import Fault


def install_trigger(db_path: str | Path, fault: Fault) -> None:
    """Make writes to a table abort, the way a full disk or a corrupt page would."""
    if fault.adapter != "sqlite":
        raise ValueError(f"{fault.name} is not a sqlite fault")
    con = sqlite3.connect(db_path)
    try:
        con.execute(fault.params["sql"])
        con.commit()
    finally:
        con.close()


def apply_file_fault(path: str | Path, fault: Fault) -> None:
    if fault.adapter != "file":
        raise ValueError(f"{fault.name} is not a file fault")
    Path(path).write_text(fault.params["content"])
