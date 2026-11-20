# Memory write protection recovery

`MemoryWriter::write_with_report` performs a validated write and reports partial-transfer, rollback, instruction-cache, and page-protection outcomes.

## Protection restoration ownership

When a write requires temporary page-protection elevation, the backend returns the actual previous protection. If restoring that protection fails, `WriteReport` retains a `PendingProtectionRestore` containing the exact affected range and that returned protection value. The report is not successful while a protection warning remains.

Keep the report alive and retry with:

```cpp
auto report = writer.write_with_report(address, bytes);
if (!report) {
    return std::unexpected(report.error());
}
if (!report->pending_protection_restores.empty()) {
    auto restored = writer.restore_pending_protections(*report);
    if (!restored) {
        // Keep report alive; failed tickets remain available for another retry.
        return std::unexpected(restored.error());
    }
}
```

The retry operation removes only tickets whose restoration succeeded. A failed ticket remains in the report with its original range/protection pair. The report's protection warning is cleared only after all outstanding tickets have been restored.

The rollback path reuses an existing ticket when the first write pass could not restore a page. It must not treat the temporary elevated protection as the original protection or create a second ticket that could later re-elevate the page.

## Status-only convenience API

`MemoryWriter::write` returns `Status`, so it cannot return a caller-owned report. It performs one immediate retry for a transient protection-restore failure before returning. If the failure persists, it returns an error. Callers that need explicit retry ownership and inspection of partial/rollback state must use `write_with_report`.

## Failure policy

- Never report success while a protection restoration is pending.
- Never reconstruct the original protection from a later query; use only the value returned by the successful protection-change operation.
- Do not discard a `WriteReport` with pending tickets if the caller needs to retry restoration.
- A failed rollback write remains a rollback error even if protection restoration is later recovered.
- Persistent OS protection failures require caller escalation; retry does not imply the page was restored.

The retry ticket is scoped to the exact slice passed to the memory backend. A caller must not widen, merge, or reconstruct the ticket range before retrying.
