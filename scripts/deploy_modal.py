"""Deploy ``modal_app.py`` using the operator's VAULTED Modal credentials.

CI holds exactly one secret — ``TOLLBOOTH_NOSTR_OPERATOR_NSEC`` — which is the same
single secret the Modal container itself mounts. Everything else is discovered:
``ensure_bootstrapped()`` reads the Authority's bootstrap DM for the Neon URL and the
vault key, and the Modal tokens come out of the operator's own credential vault via
``runtime.load_credentials`` — byte-for-byte the read ``_ensure_async_executor``
performs on Horizon to decide whether to dispatch detached.

Delivery of Modal credentials is already codified as Secure Courier into that vault.
Copying them into GitHub as a second pair of secrets would create a credential with no
delivery story and no revocation story, and would let CI and the runtime disagree about
which Modal workspace is real — the failure the wheel calls out at
``runtime.py`` ("silently dispatching to the wrong workspace").

The tokens never touch ``$GITHUB_ENV``, a file, or the log: they are set in this
process's environment and ``modal`` is invoked as a child of it. Nothing is printed
that would need masking.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys

_FIELDS = ["modal_token_id", "modal_token_secret", "modal_app_name"]


def _run(argv: list[str], env: dict[str, str]) -> str:
    """Run a modal CLI command, streaming nothing secret, returning its stdout."""
    proc = subprocess.run(  # noqa: S603
        argv, env=env, capture_output=True, text=True, check=False
    )
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        raise SystemExit(f"::error::{' '.join(argv)} exited {proc.returncode}")
    return proc.stdout


async def _load() -> dict[str, str]:
    # Importing the server is what registers the job runners and builds the runtime;
    # modal_app.py relies on the same import for the same reason.
    from excalibur_mcp import server

    creds = await server.runtime.load_credentials(_FIELDS)
    missing = [f for f in _FIELDS if not (creds.get(f) or "").strip()]
    if missing:
        raise SystemExit(
            "::error::the operator vault has no "
            + ", ".join(missing)
            + ". Deliver them via Secure Courier (the codified path); do not add them "
            "as GitHub secrets."
        )
    return {f: creds[f].strip() for f in _FIELDS}


def main() -> None:
    if not os.environ.get("TOLLBOOTH_NOSTR_OPERATOR_NSEC", "").strip():
        raise SystemExit(
            "::error::TOLLBOOTH_NOSTR_OPERATOR_NSEC is not set. It is the one secret "
            "this deploy needs — the same one the Modal container mounts."
        )

    creds = asyncio.run(_load())

    # The wheel resolves the detached function by (app_name, "run_job"), so a vault
    # naming one app while the source declares another means the runtime dispatches to
    # a function this deploy never created — and the scheduler reports healthy while
    # nothing runs. Catch that here, where it is one line, rather than as a stalled post.
    import modal_app

    if modal_app.app.name != creds["modal_app_name"]:
        raise SystemExit(
            f"::error::modal_app.py declares app {modal_app.app.name!r} but the vault "
            f"says the runtime dispatches to {creds['modal_app_name']!r}"
        )

    env = dict(os.environ)
    env["MODAL_TOKEN_ID"] = creds["modal_token_id"]
    env["MODAL_TOKEN_SECRET"] = creds["modal_token_secret"]

    _run(["modal", "deploy", "modal_app.py"], env)

    # A deploy that silently no-ops leaves exactly the drift this workflow exists to
    # end, and looks green doing it. Modal stamps each version with the commit it came
    # from, so assert the live version is THIS one.
    expected = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    history = _run(
        ["modal", "app", "history", creds["modal_app_name"]], {**env, "COLUMNS": "200"}
    )
    if expected not in history:
        raise SystemExit(
            f"::error::Modal has no version at {expected} — the deploy did not take"
        )
    print(f"{creds['modal_app_name']} is live at {expected}")


if __name__ == "__main__":
    main()
