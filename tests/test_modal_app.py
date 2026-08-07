"""The detached render app's identity is coupled to something outside this repo.

The wheel resolves the detached function by ``(modal_app_name, "run_job")``, and
``modal_app_name`` is an operator secret delivered by Secure Courier into the vault —
where this test cannot see it. So renaming the app here is not a local edit: the runtime
would keep dispatching to the old name, find nothing, and the scheduler would report
healthy while no post ever resolved.

CI deploys with a Modal token rather than the operator nsec (a build runner has no
business holding the credential that opens the vault), which means the deploy cannot
compare the two names for us. This test is what remains: it makes the rename loud and
deliberate instead of silent, by failing until someone acknowledges the second half of
the change.
"""

from __future__ import annotations

# The name the operator vault must also carry. Changing it is a TWO-part change:
# re-courier `modal_app_name` into the operator vault, then update this pin. Doing only
# one leaves the runtime dispatching into the void.
VAULTED_APP_NAME = "excalibur-render"


def test_the_app_name_matches_what_the_runtime_dispatches_to():
    import modal_app

    assert modal_app.app.name == VAULTED_APP_NAME, (
        f"modal_app.py declares {modal_app.app.name!r} but the runtime resolves "
        f"{VAULTED_APP_NAME!r} from the vault. Re-courier `modal_app_name` before "
        "changing this pin, or the scheduler will dispatch to a function that does "
        "not exist."
    )


def test_the_runner_is_the_operator_s_own_registered_runner():
    """`run_job` must stay a thin shim over the runtime's own dispatch.

    The point of the Modal app is to be *a place to run*, not a second implementation —
    that is what let the sealed-closure apparatus be deleted in tollbooth-dpyc 0.82.0. A
    fork in behaviour here would be invisible locally, because nothing in this repo runs
    the Modal path.
    """
    import inspect

    import modal_app

    body = inspect.getsource(modal_app.run_job.get_raw_f())
    assert "_run_job" in body, "run_job must delegate to the runtime's own dispatch"
    assert "from excalibur_mcp import server" in body, (
        "the server import must stay INSIDE the function; at container import it would "
        "also run during the image build, where no secret is mounted"
    )
