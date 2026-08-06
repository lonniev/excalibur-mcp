"""Detached execution for eXcalibur's background jobs.

The wheel's ``ModalExecutor`` spawns ``run_job(claim)`` here instead of starting an
asyncio task on Horizon. What runs is the operator's OWN registered runner —
``_resolve_dynamic_runner`` or ``_resolve_post_body_runner``, unchanged — so this
file adds a *place to run*, not a second implementation.

That is the whole reason the sealed-closure apparatus could be deleted in
tollbooth-dpyc 0.82.0. A generic remote flow could not execute this module's code,
so a job spec had to be encrypted, shipped, interpreted by an op vocabulary and
shaped on the way back. Here the code simply is the code.

**One secret, and it is the one an operator human actually knows.**

``ensure_bootstrapped()`` reads exactly ``TOLLBOOTH_NOSTR_OPERATOR_NSEC``. From the
nsec it derives the npub, finds the Authority's bootstrap DM on a Nostr relay, and
returns BOTH the Neon URL and the vault encryption key. So nothing else is copied
into Modal: no database URL (the operator human does not reliably know it — the
Authority issues it), no vault key, no provider keys. Those all live in the vault
this boot discovers.

The nsec is irreducible: it *is* the identity, and it cannot be fetched over Nostr
because decrypting a DM addressed to your npub requires the nsec you would be
fetching. Everything downstream of identity already arrives over Nostr.

Net effect: this container holds exactly what Horizon holds — no more.

Deploy::

    modal deploy modal_app.py

Then courier ``modal_token_id`` / ``modal_token_secret`` / ``modal_app_name`` into
the operator vault; the runtime installs ModalExecutor on its next job.
"""

import modal

# Must match the vaulted ``modal_app_name``; the wheel resolves the function by
# (app_name, "run_job").
app = modal.App("excalibur-render")

image = (
    modal.Image.debian_slim(python_version="3.12")
    # Dependencies from the single source of truth — the same pins the MCP runs,
    # including tollbooth-dpyc itself. A second dependency list here would drift
    # from pyproject.toml and be discovered as a version-skew bug months later.
    .pip_install_from_pyproject("pyproject.toml")
    # The operator's own package. `copy=False` mounts it at run time so a code
    # change does not force an image rebuild.
    .add_local_python_source("excalibur_mcp")
)

# Named, not inline: created once by the operator in Modal, holding the single
# field TOLLBOOTH_NOSTR_OPERATOR_NSEC.
operator_identity = modal.Secret.from_name("excalibur-operator")


@app.function(
    image=image,
    secrets=[operator_identity],
    # A render is bounded by the author's own runtimeLimit (900s ceiling) times a
    # handful of blocks. 3600 is headroom, not an expectation — and it is the only
    # ceiling in the path, since nothing here is bound to an HTTP response.
    timeout=3600,
    # Renders are I/O-bound: one provider call per block, with the provider running
    # its own tool loop server-side. Requesting more CPU would buy nothing.
    cpu=1.0,
    memory=1024,
)
def run_job(claim: str) -> None:
    """Run one claimed job to completion, detached from the caller.

    Returns ``None`` deliberately. ``_run_job`` persists its own outcome to the
    operator's Neon — success, curated situation, or refund — so the job row is the
    source of truth and this function's return value is not part of the contract.
    The wheel polls the Modal handle only to catch a run that died without writing
    a row at all (cancelled, crashed, or out of time).
    """
    import asyncio

    # Imported INSIDE the function: importing the server module registers the job
    # runners as a side effect, and doing that at container import would run it
    # during image build too, where no secret is mounted.
    from excalibur_mcp import server

    asyncio.run(server.runtime._run_job(claim))
