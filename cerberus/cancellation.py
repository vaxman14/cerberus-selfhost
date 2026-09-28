class ScanCancelled(RuntimeError):
    """Raised when the operator stops an in-progress scan."""


def check(cancel_event) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise ScanCancelled("scan stopped by operator")
