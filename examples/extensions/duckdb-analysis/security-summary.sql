SELECT occurred_at, event_type, site_ref, route_ref, subject_hash, severity, evidence_refs, "count"
FROM audit_events
WHERE occurred_at >= ? AND occurred_at < ?
ORDER BY occurred_at, event_type, site_ref, route_ref
LIMIT 10000
