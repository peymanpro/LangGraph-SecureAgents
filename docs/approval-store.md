# Durable human-approval grants

The middleware can enforce a one-time approval grant instead of relying on an application-defined validator callback. `SQLiteApprovalStore` stores only a hash of the opaque bearer token, binds the grant to the exact request fingerprint and a reviewer ID, applies an expiry, and atomically consumes it before a permitted tool handler runs.

## Configure the store

    from langgraph_secure_agents import SQLiteApprovalStore
    from langgraph_secure_agents.middleware import create_authorization_middleware

    approval_store = SQLiteApprovalStore("/var/lib/my-service/approvals.sqlite3")

    def resolve_trusted_reviewer(runtime_context: object) -> str:
        # Resolve the authenticated reviewer from server-trusted, request-scoped
        # identity state. Do not read reviewer identity from the model or approval
        # response. Replace this line with your authentication integration.
        return authentication_layer.current_reviewer().subject

    authorization = create_authorization_middleware(
        policy,
        principal_resolver=resolve_principal,
        approval_store=approval_store,
        approval_reviewer_resolver=resolve_trusted_reviewer,
    )

The resolver is called when a resumed approval is validated. It must return the reviewer identity authenticated by the host for that resume request. In some LangGraph integrations, the original graph runtime context remains unchanged across resume; in those integrations, use trusted request-scoped state (for example, a context variable established by the authenticated resume endpoint) rather than assuming that the graph context automatically changes to the reviewer. Never trust a `reviewer_id` field supplied inside the approval payload.

## Issue and resume a grant

The interrupt payload includes `request_fingerprint`. Your authenticated approval endpoint must verify that the reviewer may approve that pending operation and that the reviewer approved this exact request before issuing a token:

    from datetime import timedelta

    fingerprint = pending_interrupt["request_fingerprint"]
    token = approval_store.issue(
        fingerprint,
        reviewer_id=authenticated_reviewer.subject,
        ttl=timedelta(minutes=3),
    )

Resume the exact paused graph with an approval value containing the token and original fingerprint:

    resume_value = {
        "approved": True,
        "request_fingerprint": fingerprint,
        "approval_token": token,
    }

The middleware checks the fingerprint, resolves the trusted reviewer identity, and consumes the token using one conditional database update within a write transaction. A wrong fingerprint, wrong reviewer, expired token, unknown token, or replay fails closed and does not invoke the tool handler. The database enforces one grant per request fingerprint so a second token cannot be issued for the same fingerprint while its grant record remains. Use unique tool-call/operation IDs; a new approval attempt should represent a new operation fingerprint.

A rejection does not need a grant because it can only deny execution. The host must still authenticate the reviewer and protect the endpoint that accepts the rejection or resumes the graph.

## Operations and limits

- Use a persistent database path, not `:memory:`, when approvals must survive process restart.
- SQLite transactions serialize consumption for threads and processes using the same local database. For horizontally distributed deployments, use a shared transactional backend implementing the `ApprovalStore` protocol; do not put a SQLite database on an unsuitable network filesystem.
- Tokens are bearer secrets. Deliver them only through the trusted approval/resume path, avoid logging them, and use a short TTL.
- The store does not authenticate reviewers, authorize which person may approve a request, secure the resume endpoint, or protect the host's authentication state. Those responsibilities remain with the application.
- The store does not delete expired rows automatically. Call `purge_expired()` according to your retention requirements; it removes expired grants only.
- Database errors propagate instead of being converted into successful validation. The middleware therefore fails closed if durable consumption cannot be confirmed.

The older `approval_validator` callback remains available for applications that supply a different transactional store. Configure either `approval_store` with `approval_reviewer_resolver` or `approval_validator`, not both.
