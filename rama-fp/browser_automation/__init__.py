"""The fp browser journey shared by local tests and BrowserStack collection.

Browser automation triggers real page APIs. Packet capture and profile replay live
in the test harness, so the nightly collector can reuse this journey without a
local database, packet privileges, or a Rama client.
"""

from .workflow import FlowResult, run_capture_flow

__all__ = ["FlowResult", "run_capture_flow"]
