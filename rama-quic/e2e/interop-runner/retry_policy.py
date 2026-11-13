"""When one failed cell of a probabilistic case group is run a second time.

The loss and corruption cases drop or damage packets at random, and a 50-handshake cell
fails on one unlucky handshake. A single such cell in a job is run once more. Anything
wider fails as it stands: more than one cell, a cell outside those groups, or a cell that
also failed first in the previous workflow run, which is no longer an isolated event.
"""
from check_results import InvalidResults


def failed_cells(report):
    """Every (client, server, case) the upstream report marks failed."""
    try:
        servers = report["servers"]
        return [(client, server, entry["name"])
                for ci, client in enumerate(report["clients"])
                for si, server in enumerate(servers)
                for entry in report["results"][ci * len(servers) + si]
                if entry["result"] == "failed"]
    except (KeyError, IndexError, TypeError) as error:
        raise InvalidResults(f"report does not list its cells: {error}") from error


def previous_first_failures(record):
    """The cells the previous workflow run recorded as failing first, and where it ran."""
    if (not isinstance(record, dict) or set(record) != {"run", "first_failures"}
            or not (record["run"] is None or isinstance(record["run"], str))
            or not isinstance(record["first_failures"], list)):
        raise InvalidResults("previous run record must hold exactly run and first_failures")
    cells = set()
    for cell in record["first_failures"]:
        if (not isinstance(cell, dict) or set(cell) != {"client", "server", "case"}
                or not all(isinstance(value, str) and value for value in cell.values())):
            raise InvalidResults("previous run record names an invalid cell")
        cells.add((cell["client"], cell["server"], cell["case"]))
    return record["run"], cells


def decide(*, group, retried_groups, failures, previous):
    """The one cell to run again as (role, cell, None), or (None, None, why not).

    `failures` maps each failed role to the cells its report marks failed, or to None when
    the report could not say. `previous` is the previous run's record, or None when the
    caller has none; without it nothing is retried.
    """
    if group not in retried_groups:
        return None, None, f"only the {', '.join(retried_groups)} case groups are retried"
    if previous is None:
        return None, None, "no record of the previous workflow run was supplied"
    cells = [(role, cell) for role, found in failures.items() for cell in found or ()]
    if any(not found for found in failures.values()) or len(cells) != 1:
        return None, None, (f"{len(cells)} cells failed over {len(failures)} failed roles; "
                            "exactly one cell in one role is retried")
    role, cell = cells[0]
    run, before = previous
    if cell in before:
        return None, None, ("the same cell also failed first in the previous workflow run"
                            + (f" ({run})" if run else ""))
    return role, cell, None
