# Structured authorization audit events

**AuditEvent** is a versioned record of an authorization decision at a configured execution boundary. It gives log pipelines and tracing systems a stable shape without copying prompt text, raw tool arguments, or ABAC attribute values into the event.

## Enable an audit callback

The core event type and JSON serialization do not require OpenTelemetry. The custom callback receives an AuditEvent object:

~~~python
from langgraph_secure_agents import AuditEvent, protect_callable


def record_event(event: AuditEvent) -> None:
    # Use include_sensitive=True only because this sink is trusted.
    durable_audit_store.write(event.to_json(include_sensitive=True))


guarded_lookup = protect_callable(
    lookup_report,
    policy=policy,
    principal_resolver=current_principal,
    action="read",
    resource_resolver=lambda report_id: f"report:{report_id}",
    audit_event_callback=record_event,
    request_id_resolver=lambda report_id: current_request_id(),
    execution_id_resolver=current_execution_id,
    policy_id="report-access",
    policy_version="2.1.0",
    policy_digest=deployed_bundle.digest,
)
~~~

request_id_resolver receives the same arguments as the protected callable, through the library's detached-copy resolver boundary. execution_id_resolver takes no arguments. Use trusted application context for both; do not derive identity or correlation values from model-generated claims. These optional resolvers are only evaluated when audit_event_callback is configured.

For LangChain/LangGraph tools, create_authorization_middleware accepts the same audit_event_callback and policy metadata parameters. Middleware events carry the tool-call ID as request_id, the runtime task ID as execution_id when available, and the tool name separately from the policy resource. The optional MCP adapter emits the same event shape with source mcp_tool, the MCP Context request ID where available, and the registered tool name; it does not synthesize an execution_id.

## Event schema

Every event has schema version 1, event name authorization.decision, a unique event_id, a UTC timestamp, source, action, decision result and reason, approval status, matched-rule count, optional policy ID/version, and optional evaluation duration. When available, the event also carries request ID, execution ID, tool name, and policy digest internally.

| Field | Meaning |
| --- | --- |
| event_id | Unique ID for this emitted event. It is not a stable request correlation ID. |
| timestamp | Time the event was created, normalized to UTC. |
| source | Boundary that produced the event, such as python_callable, langchain_tool, or mcp_tool. |
| action, resource, tool_name | The action and resource evaluated; the tool name is separate when emitted by middleware. |
| allowed, decision_reason, requires_approval | Machine-readable outcome and whether a policy decision requires a human response. |
| matched_rule_count, matched_rule_ids | Number of matched rules; IDs are sensitive and omitted from default serialization. |
| policy_id, policy_version, policy_digest | Optional metadata supplied by the application for the evaluated policy bundle. |
| duration_ms | Elapsed time used to resolve the request and evaluate the policy, not protected-operation runtime. |
| request_id, execution_id | Optional correlation values supplied by the application or agent runtime. |

Use DecisionReason values instead of parsing free-form text. The event captures the authorization decision; it does not report whether the business operation later succeeded or what data it returned.

## Privacy defaults

AuditEvent.to_dict() and to_json() redact principal IDs and roles, resource identifiers, matched rule IDs, policy digest, request/execution IDs, and tool name by default. They retain the event ID, timestamp, source, action, decision reason, result, matched-rule count, policy ID/version, and duration.

~~~python
redacted_record = event.to_dict()
trusted_record = event.to_dict(include_sensitive=True)
json_line = event.to_json()  # Redacted by default
~~~

The AuditEvent object delivered to a custom callback still contains the sensitive fields. Redaction applies to the built-in serializers and OpenTelemetry adapter, not to arbitrary callback code. Only pass events to trusted sinks and enable include_sensitive=True after reviewing retention, access control, and data-protection requirements. Raw principal/resource/context attribute values, full tool arguments, and model-generated content are not copied into the event.

## Optional OpenTelemetry adapter

Install the extra:

~~~bash
python -m pip install "langgraph-secure-agents[opentelemetry]"
~~~

Then configure the adapter as the event callback:

~~~python
from langgraph_secure_agents import create_opentelemetry_callback
from langgraph_secure_agents.middleware import create_authorization_middleware

audit_to_otel = create_opentelemetry_callback()

middleware = create_authorization_middleware(
    policy,
    principal_resolver=resolve_principal,
    audit_event_callback=audit_to_otel,
    policy_id=bundle.policy_id,
    policy_version=bundle.version,
    policy_digest=bundle.digest,
)
~~~

The adapter attaches an authorization.decision event to the current recording span. If there is no recording span, it creates a short span around the event. Sensitive fields are omitted unless the adapter is created with include_sensitive=True. The adapter does not configure an exporter, persist records, retry delivery, or manage an OpenTelemetry collector; configure those facilities in the host application.

## Human-approval events

For middleware calls whose policy decision is approval_required, the structured callback receives an event before the interrupt is raised. This makes a pending approval visible even if the graph is never resumed. After resume, the callback receives another event for the final result: human_approved, approval_denied, or approval_invalid.

The legacy audit_callback(request, decision) remains supported. For approval-required calls, it continues to receive the final outcome only; the new structured callback additionally reports the pending policy decision. If both callbacks are configured, the structured event callback runs first.

## Failure behavior and operational responsibility

Auditing is synchronous at the enforcement boundary. If a configured callback raises, the protected callable or middleware tool handler is not invoked. The exception propagates to the host application. This is intentional fail-closed behavior: a host that requires a durable audit record before side effects should use a sink that confirms persistence before returning successfully.

## Durable SQLite sink and integrity checks

For synchronous persistence, use the built-in `SQLiteAuditSink` as the structured event callback:

    from langgraph_secure_agents import SQLiteAuditSink, protect_callable

    audit_sink = SQLiteAuditSink("/var/lib/my-service/authorization-audit.sqlite3")
    protected = protect_callable(
        read_report,
        policy=policy,
        principal_resolver=current_principal,
        audit_event_callback=audit_sink,
    )

The callback returns only after the SQLite transaction commits. A database failure propagates to the guard or middleware and prevents the protected operation from executing. The sink uses privacy-safe event serialization by default; enable `include_sensitive=True` only when the database and its operators are authorized to access principal IDs, roles, resource identifiers, matched rule IDs, correlation IDs, and policy digests.

Each record contains the previous record's hash and a SHA-256 hash over its sequence, previous hash, and canonical serialized event. Call `audit_sink.verify_integrity()` to check the retained chain. This is tamper-evident against individual record modification, deletion, or reordering, but it is not tamper-proof: an actor able to rewrite the entire database can recompute the chain. For stronger assurance, periodically export and anchor chain heads in a separately controlled system.

The sink is synchronous and does not provide a background retry queue, automatic retention/deletion, an access-control system, or a remote archive. SQLite's busy timeout handles brief lock contention; persistent failures still raise and fail closed. Records are not pruned automatically because deletion breaks the retained chain. Plan database access controls, backups, archival, retention, monitoring, disk capacity, and any external chain-head anchoring as operational controls.

The library also does not emit events for failures that occur before an authorization request and decision can be constructed, such as an exception in a principal resolver. Avoid logging raw request data in exception handlers.

For the overall trust boundaries, see the threat model (threat-model.md).
