"""Key logs (SSLKEYLOGFILE): ingest, list, and remove.

A key log is the only legitimate source of the secrets used by
``POST /streams/{id}/decrypt``. It is handled the way the rest of the product
handles evidence:

* it is stored under a server-generated name with owner-only permissions, and
  the user-supplied name is display-only and never becomes a path;
* its SHA-256 is recorded so the operator can prove which file was used;
* the file's own contents are never returned by the API — only what it carries
  (labels and counts), because a secret has no place in a report.

What is *not* here: any retrieval of a private key, and any derivation of
secrets from observed traffic. Decryption without an operator-supplied key log
is not possible, by design.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile, status
from sqlalchemy import select

from ...analyzers.tls_decryption import describe_keylog, parse_keylog
from ...core.errors import LimitExceeded, NotFound
from ...models import KeyLog
from ..context import ContextDep, SessionDep, StorageDep
from ...schemas.api import KeyLogOut

router = APIRouter()

STREAM_CHUNK = 512 * 1024
# A key log is a few hundred lines of text. Anything larger is a mistake, and
# refusing it is cheaper than copying it into storage.
MAX_KEYLOG_BYTES = 2 * 1024 * 1024


def _keylog_dir(storage, project_id: str) -> Path:
    path = storage.project_dir(project_id) / "keylogs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load_keylog(session, project_id: str, keylog_id: str) -> KeyLog:
    row = session.get(KeyLog, keylog_id)
    if row is None or row.project_id != project_id:
        raise NotFound(f"Key log {keylog_id!r} does not exist in this project.")
    return row


def _out(row: KeyLog) -> KeyLogOut:
    return KeyLogOut(
        id=row.id,
        project_id=row.project_id,
        name=row.name,
        sha256=row.sha256,
        size_bytes=row.size_bytes,
        line_count=row.line_count,
        labels=row.labels or {},
        created_at=row.created_at,
    )


@router.post(
    "/projects/{project_id}/keylogs",
    response_model=KeyLogOut,
    status_code=status.HTTP_201_CREATED,
)
async def upload_keylog(
    project_id: str,
    session: SessionDep,
    storage: StorageDep,
    settings: ContextDep,
    file: Annotated[UploadFile, File()],
    name: Annotated[str | None, Form()] = None,
) -> KeyLogOut:
    """Store one key log and record what it carries.

    The file is parsed before it is kept: a key log that holds nothing usable is
    reported rather than silently stored, because "I gave it a key log" is not
    the same as "this build can use it".
    """
    display = (name or file.filename or "keylog").strip()[:200] or "keylog"
    written = 0
    digest = hashlib.sha256()
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".keylog") as handle:
            temp_path = Path(handle.name)
            while True:
                chunk = await file.read(STREAM_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_KEYLOG_BYTES:
                    raise LimitExceeded(
                        "The key log is larger than the maximum this build accepts.",
                        details={"limit_bytes": MAX_KEYLOG_BYTES},
                    )
                digest.update(chunk)
                handle.write(chunk)
        text = temp_path.read_text(encoding="utf-8", errors="replace")
        entries = parse_keylog(text)
        summary = describe_keylog(entries)

        directory = _keylog_dir(storage, project_id)
        stored = directory / digest.hexdigest()[:32]
        stored.write_bytes(temp_path.read_bytes())
        # Owner-only: a key log holds secrets.
        stored.chmod(0o600)

        row = KeyLog(
            project_id=project_id,
            name=display,
            storage_path=str(stored),
            sha256=digest.hexdigest(),
            size_bytes=written,
            line_count=len(text.splitlines()),
            labels=summary["labels"],
        )
        session.add(row)
        session.commit()
        return _out(row)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)


@router.get("/projects/{project_id}/keylogs", response_model=list[KeyLogOut])
def list_keylogs(
    project_id: str,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[KeyLogOut]:
    rows = list(
        session.execute(
            select(KeyLog)
            .where(KeyLog.project_id == project_id)
            .order_by(KeyLog.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [_out(row) for row in rows]


@router.delete("/projects/{project_id}/keylogs/{keylog_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_keylog(
    project_id: str,
    keylog_id: str,
    session: SessionDep,
    storage: StorageDep,
) -> Response:
    row = _load_keylog(session, project_id, keylog_id)
    path = Path(row.storage_path)
    # Only ever delete inside this project's own key log directory: the stored
    # path came from us, but containment is not something to take on trust.
    try:
        if path.is_file() and _keylog_dir(storage, project_id) in path.parents:
            path.unlink()
    except OSError:
        # A missing file is the desired end state; a permission error is the
        # operator's to fix, and the record is still removed.
        pass
    session.delete(row)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
