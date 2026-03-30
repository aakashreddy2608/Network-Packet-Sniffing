from __future__ import annotations

import threading
from typing import Any, Callable, Optional


PacketCallback = Callable[[Any], None]

#
# Global flag requested by requirements.
# It is toggled by PacketSniffer.start()/stop() and observed via stop_filter.
#
sniffing = False


def list_interfaces() -> list[str]:
    """
    Return available interfaces (best-effort).
    """
    try:
        from scapy.all import get_if_list  # type: ignore
    except Exception:
        return []
    try:
        return list(get_if_list())
    except Exception:
        return []


class PacketSniffer:
    """
    Threaded Scapy sniffer that stays GUI-friendly.

    Workflow (per packet):
      on_packet(pkt) is called from the sniffing thread.
      The caller should ensure any Tkinter UI updates are marshalled to the main thread.
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        on_packet: Optional[PacketCallback] = None,
        bpf_filter: Optional[str] = None,
    ) -> None:
        self.iface = iface
        self.on_packet = on_packet
        self.bpf_filter = bpf_filter

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running():
            return
        global sniffing
        sniffing = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="PacketSnifferThread", daemon=True)
        self._thread.start()

    def stop(self, join_timeout_s: float = 0.2) -> None:
        global sniffing
        sniffing = False
        self._stop_event.set()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=join_timeout_s)

    def _run(self) -> None:
        try:
            from scapy.all import sniff  # type: ignore
        except Exception as e:
            # Can't raise across threads nicely; just stop.
            self._stop_event.set()
            global sniffing
            sniffing = False
            return

        def _stop_filter(_: Any) -> bool:
            # Stop when either the global flag or the instance stop event is set.
            return (not sniffing) or self._stop_event.is_set()

        def _prn(pkt: Any) -> None:
            # Never run user callback after stop is requested.
            if (not sniffing) or self._stop_event.is_set():
                return
            if self.on_packet is not None:
                try:
                    self.on_packet(pkt)
                except Exception:
                    # Never let user callback kill the sniffer thread
                    return

        # store=False avoids memory growth inside scapy; caller stores if needed.
        # Use a short timeout loop so the stop button can stop quickly even
        # when no packets are arriving.
        while (not self._stop_event.is_set()) and sniffing:
            sniff(
                iface=self.iface,
                prn=_prn,
                store=False,
                stop_filter=_stop_filter,
                filter=self.bpf_filter,
                timeout=0.5,
            )
