"""
Policy Transformer
Transforms frontend policy config format to backend conditions/actions format
"""

from typing import Dict, Any, List, Optional, Tuple


def transform_frontend_config_to_backend(
    policy_type: str, config: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform frontend config format to backend conditions/actions format

    Args:
        policy_type: Policy type ('clipboard_monitoring', 'file_system_monitoring', etc.)
        config: Frontend config dictionary

    Returns:
        Tuple of (conditions_dict, actions_dict)
    """
    if policy_type == "clipboard_monitoring":
        return _transform_clipboard_config(config)
    elif policy_type == "file_system_monitoring":
        return _transform_file_system_config(config)
    elif policy_type == "file_transfer_monitoring":
        return _transform_file_transfer_config(config)
    elif policy_type == "usb_device_monitoring":
        return _transform_usb_device_config(config)
    elif policy_type == "usb_file_transfer_monitoring":
        return _transform_usb_transfer_config(config)
    elif policy_type == "google_drive_local_monitoring":
        return _transform_google_drive_local_config(config)
    elif policy_type == "google_drive_cloud_monitoring":
        return _transform_google_drive_cloud_config(config)
    elif policy_type == "onedrive_cloud_monitoring":
        return _transform_onedrive_cloud_config(config)
    elif policy_type == "file_identity_denylist":
        return _transform_file_identity_denylist_config(config)
    elif policy_type == "email_send_prevention":
        return _transform_email_config(config)
    elif policy_type == "messaging_app_control":
        return _transform_messaging_app_control_config(config)
    elif policy_type == "application_control":
        return _transform_application_control_config(config)
    elif policy_type == "network_share_transfer_control":
        return _transform_network_share_transfer_config(config)
    elif policy_type == "web_activity_control":
        return _transform_web_activity_config(config)
    else:
        # Unknown type, return empty defaults
        return (
            {"match": "all", "rules": []},
            {"log": {}},
        )


def _transform_clipboard_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform clipboard monitoring config to backend format
    
    # ... (rest of the function)
    """
    patterns = config.get("patterns", {})
    predefined = patterns.get("predefined", [])
    custom = patterns.get("custom", [])
    action = config.get("action", "log")

    # Predefined pattern regexes.
    #
    # IMPORTANT: this dict must cover every pattern `id` offered by the
    # frontend picker (dashboard/src/utils/policyUtils.ts's
    # `predefinedPatterns` array -- ClipboardPolicyForm.tsx renders every
    # entry in that array as a checkbox with no filtering). Previously this
    # dict only had 7 of the 17 ids the UI actually offers -- selecting any
    # of the other 10 (all the Indian-identifier types: aadhaar, pan, ifsc,
    # indian_bank_account, indian_phone, upi_id, micr, indian_dob, plus
    # source_code_content and api_key_in_code/database_connection_string)
    # silently produced ZERO enforcement rules for that pattern (the lookup
    # below just skips ids that aren't in this dict -- no error, no warning).
    # A user who ticked "Aadhaar Number" or "PAN Number" thinking their
    # clipboard policy would catch it got a policy that matched nothing.
    #
    # Also fixes several regexes that were simply wrong (kept in sync with
    # the same fixes applied to server/data/default_rules.json and
    # main.py's _patch_default_rule_patterns() for the classification-rules
    # engine -- these are a separate enforcement path but the same bug
    # classes applied):
    #   - credit_card: was 16-digits-only, could never match a real Amex
    #     (15 digits) or Diners Club (14 digits) card.
    #   - email: `[A-Z|a-z]` included a literal `|` in the character class.
    #   - api_key: was a bare `\b[A-Za-z0-9_-]{32,}\b` -- matches almost
    #     any long token, hash, or UUID pasted into the clipboard. Replaced
    #     with known vendor key formats (AWS/GitHub/Slack/Stripe/Google) plus
    #     a labeled `api_key: "..."`-style fallback, so it stops firing on
    #     arbitrary long strings that merely happen to be 32+ characters.
    #   - private_key: missed encrypted PEM keys and PGP private key blocks.
    predefined_patterns = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:(?:\d{4}[\s-]?){3}\d{4}|3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}|3(?:0[0-5]\d|[68]\d{2})[\s-]?\d{6}[\s-]?\d{4})\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "api_key": r"(?i)(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}|gh[oprsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|xox[baprs]-[0-9A-Za-z-]{10,72}|(?:sk|rk)_live_[0-9A-Za-z]{24,}|AIza[0-9A-Za-z_-]{35}|(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_-]{20,}[\"']?",
        "private_key": r"-----BEGIN (RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "password": r"(?i)(password|pwd|passwd)\s*[:=]\s*\S+",
        # Indian identifiers -- previously entirely unenforced despite being
        # selectable in the UI.
        "aadhaar": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "pan": r"\b[A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z]\b",
        "ifsc": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        "indian_bank_account": r"\b\d{9,18}\b",
        "indian_phone": r"\b(\+91|91|0)?[6-9]\d{9}\b",
        "upi_id": r"\b[\w.-]+@(paytm|phonepe|ybl|okaxis|okhdfcbank|oksbi|okicici)\b",
        "micr": r"\b\d{9}\b",
        "indian_dob": r"\b(0[1-9]|[12][0-9]|3[01])[/-](0[1-9]|1[0-2])[/-](19|20)\d{2}\b",
        # Source code / secrets-in-code -- also previously unenforced.
        "source_code_content": r"\b(function|def|class|public|private|protected|static|import|from|require|include|using|package|const|let|var|int|string|float|bool)\s+\w+",
        "api_key_in_code": r"(?i)(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}|gh[oprsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|api[_-]?key[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]{32,}[\"']?",
        "database_connection_string": r"(jdbc:(mysql|postgresql|oracle|sqlserver)://|mongodb://|mongodb\+srv://|redis://|rediss://|postgres(?:ql)?://|mysql://|amqp://|amqps://)",
    }

    rules = []

    # Add predefined patterns
    for pattern_id in predefined:
        if pattern_id in predefined_patterns:
            rules.append(
                {
                    "field": "clipboard_content",
                    "operator": "matches_regex",
                    "value": predefined_patterns[pattern_id],
                }
            )

    # Add custom patterns
    for custom_pattern in custom:
        regex = custom_pattern.get("regex", "")
        if regex:
            rules.append(
                {
                    "field": "clipboard_content",
                    "operator": "matches_regex",
                    "value": regex,
                }
            )

    # If no pattern rules were configured, still match all clipboard events so
    # the policy fires on every clipboard copy (useful for audit/log policies).
    if not rules:
        rules.append(
            {
                "field": "event_type",
                "operator": "equals",
                "value": "clipboard",
            }
        )

    # Build conditions
    conditions = {
        "match": "any" if len(rules) > 1 else "all",
        "rules": rules,
    }

    # Build actions
    actions = {action: {}}

    return conditions, actions


# ... (other transformation functions)


def _transform_google_drive_cloud_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform Google Drive cloud monitoring config to backend format

    Frontend format:
    {
        "connectionId": "uuid...",
        "protectedFolders": [
            {"id": "folder_id_1", "name": "Folder 1"},
            {"id": "folder_id_2", "name": "Folder 2"}
        ],
        "pollingInterval": 10,
        "action": "log"
    }

    Backend format:
    conditions: {
        "match": "all",
        "rules": [
            {"field": "source", "operator": "equals", "value": "google_drive_cloud"},
            {"field": "connection_id", "operator": "equals", "value": "..."},
            {"field": "folder_id", "operator": "in", "value": ["folder_id_1", ...]}
        ]
    }
    actions: {
        "log": {}
    }
    """
    connection_id = config.get("connectionId")
    protected_folders = config.get("protectedFolders", [])
    # action = config.get("action", "log") # Always log for now

    rules = []

    # 1. Match source
    rules.append(
        {
            "field": "source",
            "operator": "equals",
            "value": "google_drive_cloud",
        }
    )

    # 2. Match connection ID
    if connection_id:
        rules.append(
            {
                "field": "connection_id",
                "operator": "equals",
                "value": connection_id,
            }
        )

    # 3. Match folder IDs (if any)
    folder_ids = [f.get("id") for f in protected_folders if f.get("id")]
    if folder_ids:
        rules.append(
            {
                "field": "folder_id",
                "operator": "in",
                "value": folder_ids,
            }
        )

    # Build conditions
    conditions = {
        "match": "all",
        "rules": rules,
    }

    # Build actions (Cloud monitoring is currently log-only)
    actions = {"log": {}}

    return conditions, actions


def _transform_onedrive_cloud_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform OneDrive cloud monitoring config to backend format

    Frontend format:
    {
        "connectionId": "uuid...",
        "protectedFolders": [
            {"id": "folder_id_1", "name": "Folder 1"},
            {"id": "folder_id_2", "name": "Folder 2"}
        ],
        "pollingInterval": 10,
        "action": "log"
    }

    Backend format:
    conditions: {
        "match": "all",
        "rules": [
            {"field": "source", "operator": "equals", "value": "onedrive_cloud"},
            {"field": "connection_id", "operator": "equals", "value": "..."},
            {"field": "folder_id", "operator": "in", "value": ["folder_id_1", ...]}
        ]
    }
    actions: {
        "log": {}
    }
    """
    connection_id = config.get("connectionId")
    protected_folders = config.get("protectedFolders", [])
    # action = config.get("action", "log") # Always log for now

    rules = []

    # 1. Match source
    rules.append(
        {
            "field": "source",
            "operator": "equals",
            "value": "onedrive_cloud",
        }
    )

    # 2. Match connection ID
    if connection_id:
        rules.append(
            {
                "field": "connection_id",
                "operator": "equals",
                "value": connection_id,
            }
        )

    # 3. Match folder IDs (if any)
    folder_ids = [f.get("id") for f in protected_folders if f.get("id")]
    if folder_ids:
        rules.append(
            {
                "field": "folder_id",
                "operator": "in",
                "value": folder_ids,
            }
        )

    # Build conditions
    conditions = {
        "match": "all",
        "rules": rules,
    }

    # Build actions (Cloud monitoring is currently log-only)
    actions = {"log": {}}

    return conditions, actions


def _transform_file_system_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform file system monitoring config to backend format

    Frontend format:
    {
        "monitoredPaths": ["C:\\Users\\...", "D:\\..."],
        "fileExtensions": [".pdf", ".docx"],
        "events": {
            "create": true,
            "modify": true,
            "delete": false,
            "move": true
        },
        "action": "alert" | "log" | "quarantine" | "block",
        "quarantinePath": "C:\\ProgramData\\SeceoKnight\\quarantine" (optional, for quarantine action)
    }

    Backend format:
    conditions: {
        "match": "all",
        "rules": [
            {"field": "file_path", "operator": "starts_with", "value": "..."},
            {"field": "event_type", "operator": "in", "value": ["create", "modify", ...]},
            {"field": "file_extension", "operator": "in", "value": [".pdf", ...]} (if specified)
        ]
    }
    actions: {
        "alert": {} | "quarantine": {"path": "..."} | "block": {} | "log": {}
    }
    """
    monitored_paths = config.get("monitoredPaths", [])
    file_extensions = config.get("fileExtensions", [])
    events = config.get("events", {})
    action = config.get("action", "log")
    quarantine_path = config.get("quarantinePath")

    rules = []

    # Add path rules (any of the monitored paths)
    if monitored_paths:
        if len(monitored_paths) == 1:
            rules.append(
                {
                    "field": "file_path",
                    "operator": "starts_with",
                    "value": monitored_paths[0],
                }
            )
        else:
            # Multiple paths - use "in" operator
            rules.append(
                {
                    "field": "file_path",
                    "operator": "matches_any_prefix",
                    "value": monitored_paths,
                }
            )

    # Add event type rules (copy is not supported for local filesystem monitoring yet)
    event_name_map = {
        "create": "file_created",
        "modify": "file_modified",
        "delete": "file_deleted",
        "move": "file_moved",
    }
    enabled_events = [
        event_name_map.get(event, event)
        for event, enabled in events.items()
        if enabled
    ]
    if enabled_events:
        rules.append(
            {
                "field": "event_subtype",
                "operator": "in",
                "value": enabled_events,
            }
        )

    # Add file extension rules (if specified)
    if file_extensions:
        rules.append(
            {
                "field": "file_extension",
                "operator": "in",
                "value": file_extensions,
            }
        )

    # Build conditions
    conditions = {
        "match": "all",
        "rules": rules,
    }

    # File-write events (local saves to a monitored folder like Downloads)
    # now support the same quarantine/block enforcement as USB transfer and
    # file transfer policies, instead of being detection-only. The agent
    # side (ContentClassifier::Classify / HandleFileEvent in agent.cpp) has
    # always supported enforcing "quarantine"/"block" generically for any
    # matched policy — this was the one policy type deliberately withheld
    # from that capability. Falls back to "log" for any unrecognized value.
    if action not in {"alert", "log", "quarantine", "block"}:
        action = "log"

    actions: Dict[str, Any] = {}
    if action == "quarantine" and quarantine_path:
        actions["quarantine"] = {"path": quarantine_path}
    else:
        actions[action] = {}

    return conditions, actions


def _transform_email_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform email DLP (outbound) config to backend format.

    Unlike printer_control/print_content_prevention/messaging_app_control --
    which are agent-polled config toggles read directly off Policy.config by
    a dedicated GET /agents/{id}/<x>-policy endpoint -- the SMTP relay
    (smtp-relay/app/dlp_client.py) has no polling loop. It's a synchronous
    server-side component that POSTs each outbound message's extracted text
    straight to the generic /agents/{id}/policy/evaluate endpoint (event_type
    "email_send", destination_type "email") and expects an inline block/
    allow decision back from DatabasePolicyEvaluator's conditions/actions
    rule engine -- the exact same path usb_file_transfer_monitoring already
    uses. So this needs a real conditions/rules translation, not an empty
    fallback: without it, every email evaluation matches zero policies and
    silently returns allow regardless of what an admin configures in the UI.

    Frontend format:
    {
        "action": "block" | "alert" | "log",
        "triggerLevels": ["Confidential", "Restricted"]   // Public/Internal optional
    }

    Backend format:
    conditions: {
        "match": "all",
        "rules": [
            {"field": "destination_type", "operator": "equals", "value": "email"},
            {"field": "classification_level", "operator": "in", "value": ["Confidential", "Restricted"]} (if specified)
        ]
    }
    actions: {
        "block": {} | "alert": {} | "log": {}
    }
    """
    action = config.get("action", "block")
    trigger_levels = [lvl for lvl in config.get("triggerLevels", []) if lvl]

    rules = [
        {
            "field": "destination_type",
            "operator": "equals",
            "value": "email",
        }
    ]
    if trigger_levels:
        rules.append(
            {
                "field": "classification_level",
                "operator": "in",
                "value": trigger_levels,
            }
        )

    conditions = {
        "match": "all",
        "rules": rules,
    }

    if action not in {"block", "alert", "log"}:
        action = "block"
    actions = {action: {}}

    return conditions, actions


def _transform_messaging_app_control_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform messaging app attachment control config to backend format.

    Enforcement (block/alert per configured app) is agent-side: the Windows
    agent polls GET /agents/{id}/messaging-app-policy directly (see
    FetchMessagingAppPolicy()/GetMessagingVerdict() in agent.cpp) and makes
    the block/alert decision locally before the event ever reaches the
    server -- this policy's Policy.config is never read by
    DatabasePolicyEvaluator for that live decision.

    This transform exists purely so a real conditions.rules gets persisted.
    Previously messaging_app_control fell through to the "unknown type"
    branch below -> empty rules -> evaluate_event() skips the policy
    unconditionally (`if not conditions.get("rules"): continue`). Confirmed
    live in production: a real messaging_file_selection event (Teams
    file-attach, including the honest-fallback "(unknown)" detection-gap
    path) reached MongoDB correctly, but policy_id/matched_policies stayed
    empty forever, so the Policies page's violations count for "Messaging
    App Attachment Control" stayed stuck at 0 even while real detections
    were happening.

    Matches on event_subtype alone (not event_type/channel) because
    "messaging_file_selection" is the one and only subtype
    network_exfil_monitor.cpp emits for this feature -- see
    HandleBrowserDialogFromHwnd() in network_exfil_monitor.cpp, where both
    the honest-fallback branch and the normal classified-file branch set
    f.eventSubtype = "messaging_file_selection". The per-app allow/deny
    list itself (config.apps) is intentionally NOT re-checked here: the
    agent already filtered to only managed apps before ever emitting the
    event (GetMessagingVerdict()/CanonicalMessagingAppName()), and the raw
    process name isn't reliably available server-side (EventCreate doesn't
    declare a "channel"/"process_name" field for this event type), so
    re-deriving it here would be redundant at best and wrong at worst.

    Frontend format:
    {
        "action": "alert" | "block",
        "apps": ["teams.exe", "whatsapp.exe", ...],
        "exceptions": {"users": [...], "file_types": [...]}
    }

    IMPORTANT -- the backend/reporting action here is ALWAYS "alert",
    regardless of config.action. Confirmed live in production this was a
    real bug the first time this function shipped: setting the backend
    action to "block" whenever the admin picked Block on the form caused
    DatabasePolicyEvaluator -> EventProcessor.evaluate_policies() to run
    ActionExecutor.execute_block(), which unconditionally does
    `event["blocked"] = True` with ZERO real-world verification (see
    action_executor.py's execute_block() -- it's a purely declarative
    "policy says block" flag, not a confirmation anything was actually
    blocked). That's fine for event types where the server-side pipeline
    performs or confirms the block (e.g. clipboard's synchronous
    block-decision path). It's wrong here: messaging enforcement is 100%
    agent-side -- GetMessagingVerdict()/FetchMessagingAppPolicy() in
    agent.cpp already decided and executed (or didn't) BEFORE the event
    was ever created, and the event's own honestly-reported `action` field
    (BLOCK/ALERT/ALLOW, see EmitEvent() in network_exfil_monitor.cpp) is
    already the ground truth, correctly written to `action_taken` at
    ingest (events.py's create_event()). Using "block" as the backend
    action here let the declarative flag stomp that honest value with a
    literal "blocked" even for the honest-fallback ALERT case, where the
    agent explicitly could NOT identify/inspect the file and never
    terminated anything -- the user confirmed the file went through in
    Teams while the dashboard falsely showed "blocked". Using "alert"
    unconditionally avoids ever emitting a false block claim, while
    leaving the admin's real Block/Alert choice fully intact and effective
    where it actually matters -- the agent-side enforcement decision.
    """
    conditions = {
        "match": "all",
        "rules": [
            {
                "field": "event_subtype",
                "operator": "equals",
                "value": "messaging_file_selection",
            }
        ],
    }
    actions = {"alert": {}}

    return conditions, actions


def _transform_application_control_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform application control config to backend format.

    Enforcement is 100% agent-side: the Windows agent polls
    GET /agents/{id}/application-control directly (see
    FetchApplicationControl()/IsAppActionAllowed() in agent.cpp) and decides
    allow/block for each CLI-based network exfil attempt (curl, wget,
    powershell, bitsadmin, certutil, rclone, cloud-CLI, SCP -- all funneled
    through the single "cli_upload" event_subtype in
    network_exfil_monitor.cpp) locally, before the event ever reaches the
    server -- this policy's Policy.config is never read by
    DatabasePolicyEvaluator for that live decision.

    Same bug class as messaging_app_control (see that transform's docstring
    for the original diagnosis): this policy_type was previously absent
    from this dispatcher, falling through to the "unknown type" branch ->
    empty conditions.rules -> evaluate_event() skips it unconditionally
    (`if not conditions.get("rules"): continue`). Real-time enforcement
    already worked correctly (it never depended on this file), but the
    Policies page's violations count for "Application Control" would have
    stayed stuck at 0 even when the agent genuinely blocked a disallowed
    tool -- this transform exists purely so a real conditions.rules gets
    persisted and matched events get counted.

    Matches on event_subtype alone -- "cli_upload" is the one and only
    subtype the CLI network-exfil path emits. Note this also counts CLI
    uploads blocked purely for sensitive content, independent of any
    application_control rule, since the event schema doesn't carry a field
    distinguishing "blocked by app rule" from "blocked by content
    classification" -- both are still genuine matches of "a CLI upload was
    observed/blocked", consistent with how every other config-toggle policy
    here (e.g. messaging_app_control) matches on event_subtype alone rather
    than re-deriving the agent's own decision.

    NOTE: wireless_transfer_control, print_content_prevention and
    printer_control are the same agent-polled-config-toggle style as this
    policy and messaging_app_control, and are currently ALSO missing from
    this dispatcher -- same "0 violations" display bug likely applies to
    all three. Not fixed here (out of scope for this pass); flagging for a
    follow-up.

    CORRECTION (task #151): network_share_transfer_control was originally
    listed alongside these three here, but it does NOT belong in this
    "agent already decided, this is a reporting-only gap" bucket -- unlike
    those three, its content_aware mode calls EvaluatePolicyRealtime() ->
    the shared, generic /agents/{id}/policy/evaluate endpoint, and the
    agent's actual block/allow decision for that mode depends entirely on
    DatabasePolicyEvaluator finding a matching Policy row with a "block"
    action (evaluate_policy_realtime()'s should_block only ever becomes
    True from an actual policy match or a Data Matching hit -- there is no
    "classification == Restricted -> block anyway" fallback). With this
    dispatcher falling through to the unknown-type branch, every
    content_aware Network Share Transfer Control policy silently got empty
    conditions.rules, which evaluate_event() skips outright -- meaning
    network share content-aware blocking has been completely non-functional
    (real enforcement, not just a violations counter), confirmed live: a
    file with a validated, non-test-value SSN + Luhn-valid credit card
    number classified at Confidence: 100% / Level: Restricted and still
    came back Decision: allow. See _transform_network_share_transfer_config
    below for the real fix.

    IMPORTANT -- backend/reporting action is always "alert", never mapped
    from config.mode/applications. Same reasoning as
    messaging_app_control: the agent already made and executed the real
    block/allow decision (TerminatePid) before this event was created, and
    the event's own honest `action` field (BLOCK/ALLOW, written to
    action_taken at ingest) is already ground truth. Using "block" here
    would let ActionExecutor.execute_block()'s purely declarative
    `event["blocked"] = True` override that -- with zero real-world
    verification -- for events where nothing was actually terminated (e.g.
    TerminatePid failed, or the app was in fact allowed).

    Frontend format:
    {
        "mode": "blocklist" | "allowlist",
        "applications": ["curl.exe", ...],
        "channels": ["network"]   // optional, blank = all
        "exceptions": {"applications": [...], "users": [...], "paths": [...], "file_types": [...]}
    }
    """
    conditions = {
        "match": "all",
        "rules": [
            {
                "field": "event_subtype",
                "operator": "equals",
                "value": "cli_upload",
            }
        ],
    }
    actions = {"alert": {}}

    return conditions, actions


def _transform_network_share_transfer_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform Network Share Transfer Control config to backend format.

    Task #151. Unlike messaging_app_control/application_control (agent
    already made and executed the decision before the event exists -- the
    Policy row here only matters for the dashboard's violation count),
    "content_aware" mode for this policy type is a genuine live-enforcement
    dependency: NetworkShareTransferMonitor() in agent.cpp calls
    EvaluatePolicyRealtime(..., "network_share_transfer") -> POST
    /agents/{id}/policy/evaluate, and evaluate_policy_realtime() only ever
    sets should_block=True from an actual DatabasePolicyEvaluator match (or
    a Data Matching hit) -- there is no "classification came back Restricted,
    block anyway" fallback. Before this fix, this policy_type had no case
    in the dispatcher above, so it fell through to the unknown-type branch
    and got empty conditions.rules, which evaluate_event() skips outright.
    Confirmed live: content classified at Confidence: 100% / Level:
    Restricted still came back Decision: allow, because zero Policy rows
    ever matched the event.

    Frontend format:
    {
        "mode": "block_all" | "content_aware" | "off",
        "action": "audit" | "block",
        "exception_shares": [...],   // not yet wired -- no matching agent
                                      // event field exists to key off (see
                                      // note below)
        "exception_users": [...],    // same
        "exception_paths": [...],
        "exception_file_types": [...]
    }

    "block_all" and "off" enforce (or don't) entirely agent-side --
    NetworkShareTransferMonitor() never even calls EvaluatePolicyRealtime()
    for those modes, it quarantines directly off the local mode/action
    config. The Policy row generated for those modes is for violation-count
    reporting only, matching event_subtype alone with an alert-only action,
    same reasoning as application_control/messaging_app_control: the agent
    already decided, "block" here would just be a second, disconnected
    opinion.

    "content_aware" is the mode that actually depends on this Policy row
    for its block/allow decision. Thresholds Confidential/Restricted at
    "block" (configured action) or "alert" (audit) to match the same
    severity tiers used server-side for USB in classification_engine.py's
    _determine_classification, plus an event_subtype guard so this can
    never accidentally match a different channel's event.
    """
    mode = config.get("mode", "block_all")
    action = config.get("action", "audit")
    exception_paths = config.get("exception_paths") or []
    exception_file_types = config.get("exception_file_types") or []

    rules: List[Dict[str, Any]] = [
        {
            "field": "event_subtype",
            "operator": "equals",
            "value": "network_share_transfer",
        }
    ]

    if mode == "content_aware":
        rules.append(
            {
                "field": "classification_level",
                "operator": "in",
                "value": ["Confidential", "Restricted"],
            }
        )
        if exception_paths:
            rules.append(
                {
                    "field": "source_path",
                    "operator": "not_in",
                    "value": exception_paths,
                }
            )
        if exception_file_types:
            rules.append(
                {
                    "field": "file_extension",
                    "operator": "not_in",
                    "value": exception_file_types,
                }
            )

        conditions = {"match": "all", "rules": rules}
        actions = (
            {"block": {}, "alert": {"severity": "high"}}
            if action == "block"
            else {"alert": {"severity": "medium"}}
        )
    else:
        # block_all / off: agent already decided locally. Reporting-only.
        conditions = {"match": "all", "rules": rules}
        actions = {"alert": {}}

    return conditions, actions


def _transform_web_activity_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform Web Activity Control config to backend format.

    New capability (GenAI / web-activity control). Unlike every other policy
    type in this file, the "config" here IS the whole policy -- a matrix of
    (app_category, activity) -> action (see app/core/web_activity.py for the
    vocabulary). A filled matrix has up to len(MEANINGFUL_CELLS) independent
    verdicts; the generic DatabasePolicyEvaluator conditions/actions shape
    only ever expresses ONE actions dict per policy row, so trying to force
    the matrix through that generic engine would need one Policy row per
    cell, or would silently collapse to "whichever cell happens to match
    first" -- exactly the kind of bug task #151 found in a different policy
    type. Ported approach from CyberSentinel's own commit f435920: this
    transformer intentionally emits an always-"log" placeholder, and the
    REAL evaluation reads policy.config's matrix directly -- see
    evaluate_web_activity() in app/api/v1/agents.py. policy.config is saved
    verbatim by the policies API regardless of what this function returns
    (see create_policy/policies.py), so nothing is lost.

    Frontend format:
    {
        "matrix": { "webmail.upload": "block", "genai.ai_response": "redact", ... },
        "redact_method": "placeholder"   // only method implemented so far
    }
    """
    return (
        {"match": "all", "rules": [{"field": "event_subtype", "operator": "equals", "value": "web_activity"}]},
        {"log": {}},
    )


def _transform_file_identity_denylist_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform file-identity denylist config to backend format.

    Unlike every other policy type here, this one is deliberately independent
    of content/DLP classification -- it blocks purely by *what the file is*
    (its extension, or its exact contents via hash), the same way an
    antivirus denylist works, rather than by what's *inside* it. This is
    also why it needs no dedicated matching code in
    DatabasePolicyEvaluator: "file_extension"/"file_hash" are both already
    mapped fields in its generic field/operator/value rule engine (file_hash
    was added specifically to support this policy type -- see
    database_policy_evaluator.py's _extract_field_value), so an ordinary "in"
    rule is sufficient.

    Applies to any event carrying a file_path/file_hash -- file system,
    file transfer, USB transfer, and print events all populate these fields,
    so one denylist policy covers a file however it's encountered.

    Frontend format:
    {
        "extensions": [".exe", ".bat", ".scr", ...],   // optional
        "hashes": ["<sha256 hex>", ...],                // optional
        "action": "block" | "quarantine" | "alert" | "log",
        "quarantinePath": "..." (optional, for quarantine action)
    }

    At least one of extensions/hashes should be non-empty for the policy to
    ever match anything; if both are empty this produces a policy with no
    rules, which the evaluator already skips (see evaluate_event's
    `if not conditions.get("rules"): continue`).

    Backend format:
    conditions: {
        "match": "any",
        "rules": [
            {"field": "file_extension", "operator": "in", "value": [".exe", ...]} (if specified),
            {"field": "file_hash", "operator": "in", "value": ["<sha256>", ...]} (if specified)
        ]
    }
    actions: {
        "block": {} | "quarantine": {"path": "..."} | "alert": {} | "log": {}
    }
    """
    extensions = [e.lower() for e in config.get("extensions", []) if e]
    hashes = [h.lower() for h in config.get("hashes", []) if h]
    action = config.get("action", "block")
    quarantine_path = config.get("quarantinePath")

    rules = []
    if extensions:
        rules.append(
            {
                "field": "file_extension",
                "operator": "in",
                "value": extensions,
            }
        )
    if hashes:
        rules.append(
            {
                "field": "file_hash",
                "operator": "in",
                "value": hashes,
            }
        )

    # "any" -- a file matches the denylist if it's on the extension list OR
    # its hash is on the hash list, not both. With a single rule (only one
    # of extensions/hashes configured) "any" vs "all" makes no difference.
    conditions = {
        "match": "any",
        "rules": rules,
    }

    if action not in {"alert", "log", "quarantine", "block"}:
        action = "block"

    actions: Dict[str, Any] = {}
    if action == "quarantine" and quarantine_path:
        actions["quarantine"] = {"path": quarantine_path}
    else:
        actions[action] = {}

    return conditions, actions


def _transform_google_drive_local_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform Google Drive local monitoring config to backend format

    Frontend format:
    {
        "basePath": "G:\\My Drive\\",  // Default: "G:\\My Drive\\"
        "monitoredFolders": ["Folder1", "Folder2/Subfolder"],
        "fileExtensions": [".pdf", ".docx"],  // Optional
        "events": {
            "create": true,
            "modify": true,
            "delete": false,
            "move": true
        },
        "action": "alert" | "quarantine" | "block" | "log",
        "quarantinePath": "C:\\Quarantine" (optional)
    }

    Backend format:
    conditions: {
        "match": "all",
        "rules": [
            {"field": "file_path", "operator": "matches_any_prefix", "value": ["G:\\My Drive\\Folder1", "G:\\My Drive\\Folder2\\Subfolder"]},
            {"field": "source", "operator": "equals", "value": "google_drive_local"},
            {"field": "event_subtype", "operator": "in", "value": ["file_created", "file_modified", ...]},
            {"field": "file_extension", "operator": "in", "value": [".pdf", ...]} (if specified)
        ]
    }
    actions: {
        "alert": {} | "quarantine": {"path": "..."} | "block": {} | "log": {}
    }
    """
    base_path = config.get("basePath", "G:\\My Drive\\")
    # Ensure base_path ends with backslash
    if not base_path.endswith("\\"):
        base_path = base_path + "\\"
    
    monitored_folders = config.get("monitoredFolders", [])
    file_extensions = config.get("fileExtensions", [])
    events = config.get("events", {})
    action = config.get("action", "log")
    quarantine_path = config.get("quarantinePath")

    rules = []

    # Build full paths from basePath + monitoredFolders
    full_paths = []
    if monitored_folders:
        for folder in monitored_folders:
            # Normalize folder path (remove leading/trailing slashes, normalize separators)
            folder = folder.strip().replace("/", "\\").strip("\\")
            if folder:
                full_path = base_path + folder
                # Ensure path ends with backslash for directory matching
                if not full_path.endswith("\\"):
                    full_path = full_path + "\\"
                full_paths.append(full_path)
    else:
        # If no folders specified, monitor entire base path
        full_paths.append(base_path)

    # Add path rules
    if full_paths:
        if len(full_paths) == 1:
            rules.append(
                {
                    "field": "file_path",
                    "operator": "starts_with",
                    "value": full_paths[0],
                }
            )
        else:
            rules.append(
                {
                    "field": "file_path",
                    "operator": "matches_any_prefix",
                    "value": full_paths,
                }
            )

    # Add source tag rule to identify Google Drive local events
    rules.append(
        {
            "field": "source",
            "operator": "equals",
            "value": "google_drive_local",
        }
    )

    # Add event type rules (copy is not supported for local Google Drive monitoring yet)
    event_name_map = {
        "create": "file_created",
        "modify": "file_modified",
        "delete": "file_deleted",
        "move": "file_moved",
    }
    enabled_events = [
        event_name_map.get(event, event)
        for event, enabled in events.items()
        if enabled
    ]
    if enabled_events:
        rules.append(
            {
                "field": "event_subtype",
                "operator": "in",
                "value": enabled_events,
            }
        )

    # Add file extension rules (if specified)
    if file_extensions:
        rules.append(
            {
                "field": "file_extension",
                "operator": "in",
                "value": file_extensions,
            }
        )

    # Build conditions
    conditions = {
        "match": "all",
        "rules": rules,
    }

    # Build actions
    actions = {}
    if action == "quarantine" and quarantine_path:
        actions["quarantine"] = {"path": quarantine_path}
    else:
        actions[action] = {}

    return conditions, actions


def _transform_usb_device_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform USB device monitoring config to backend format

    Frontend format:
    {
        "events": {
            "connect": true,
            "disconnect": true,
            "fileTransfer": false
        },
        "action": "alert" | "log" | "block"
    }

    Backend format:
    conditions: {
        "match": "any",
        "rules": [
            {"field": "usb_event_type", "operator": "in", "value": ["connect", "disconnect", ...]}
        ]
    }
    actions: {
        "alert": {} | "log": {} | "block": {}
    }
    """
    events = config.get("events", {})
    action = config.get("action", "log")

    enabled_events = []
    if events.get("connect"):
        enabled_events.append("connect")
    if events.get("disconnect"):
        enabled_events.append("disconnect")
    if events.get("fileTransfer"):
        enabled_events.append("file_transfer")

    rules = []
    if enabled_events:
        rules.append(
            {
                "field": "usb_event_type",
                "operator": "in",
                "value": enabled_events,
            }
        )

    # Build conditions
    conditions = {
        "match": "any" if len(enabled_events) > 1 else "all",
        "rules": rules,
    }

    # Build actions
    actions = {action: {}}

    return conditions, actions


def _transform_usb_transfer_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform USB file transfer monitoring config to backend format

    Frontend format:
    {
        "monitoredPaths": ["C:\\Users\\...", "D:\\..."],
        "action": "block" | "quarantine" | "alert",
        "quarantinePath": "C:\\Quarantine" (optional, for quarantine action)
    }

    Backend format:
    conditions: {
        "match": "all",
        "rules": [
            {"field": "source_path", "operator": "matches_any_prefix", "value": [...]},
            {"field": "destination_type", "operator": "equals", "value": "removable_drive"}
        ]
    }
    actions: {
        "block": {} | "quarantine": {"path": "..."} | "alert": {}
    }
    """
    monitored_paths = config.get("monitoredPaths", [])
    action = config.get("action", "block")
    quarantine_path = config.get("quarantinePath")

    rules = []

    # Add source path rules
    if monitored_paths:
        if len(monitored_paths) == 1:
            rules.append(
                {
                    "field": "source_path",
                    "operator": "starts_with",
                    "value": monitored_paths[0],
                }
            )
        else:
            rules.append(
                {
                    "field": "source_path",
                    "operator": "matches_any_prefix",
                    "value": monitored_paths,
                }
            )

    # Match on event_subtype sent by the agent ("usb_file_transfer").
    # Note: the agent does NOT send destination_type in the main event payload,
    # so we match event_subtype which is always present for USB file transfers.
    rules.append(
        {
            "field": "event_subtype",
            "operator": "equals",
            "value": "usb_file_transfer",
        }
    )

    # Build conditions
    conditions = {
        "match": "all",
        "rules": rules,
    }

    # Build actions
    actions = {}
    if action == "quarantine" and quarantine_path:
        actions["quarantine"] = {"path": quarantine_path}
    else:
        actions[action] = {}

    return conditions, actions


def _transform_file_transfer_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform protected->destination file transfer monitoring config to backend format

    Frontend format:
    {
        "protectedPaths": ["C:\\Sensitive", "/opt/data"],
        "monitoredDestinations": ["D:\\Staging", "/mnt/usb"],
        "fileExtensions": [".pdf", ".docx"],  // Optional
        "events": {
            "create": true,
            "modify": true,
            "delete": false,
            "move": true
        },
        "action": "block" | "quarantine" | "alert",
        "quarantinePath": "C:\\Quarantine" (optional, for quarantine action)
    }

    Backend format:
    conditions: {
        "match": "all",
        "rules": [
            {"field": "source_path", "operator": "matches_any_prefix", "value": [...]},
            {"field": "destination_path", "operator": "matches_any_prefix", "value": [...]},
            {"field": "event_subtype", "operator": "in", "value": [...]},
            {"field": "file_extension", "operator": "in", "value": [".pdf", ...]} (if specified)
        ]
    }
    actions: {
        "block": {} | "quarantine": {"path": "..."} | "alert": {}
    }
    """
    protected_paths = config.get("protectedPaths", [])
    monitored_destinations = config.get("monitoredDestinations", [])
    file_extensions = config.get("fileExtensions", [])
    events = config.get("events", {})
    action = config.get("action", "block")
    quarantine_path = config.get("quarantinePath")

    rules = []

    def _path_rule(field: str, paths: List[str]) -> Optional[Dict[str, Any]]:
        if not paths:
            return None
        if len(paths) == 1:
            return {"field": field, "operator": "starts_with", "value": paths[0]}
        return {"field": field, "operator": "matches_any_prefix", "value": paths}

    src_rule = _path_rule("source_path", protected_paths)
    if src_rule:
        rules.append(src_rule)

    dest_rule = _path_rule("destination_path", monitored_destinations)
    if dest_rule:
        rules.append(dest_rule)

    # Event mapping (we care about creates/modifies/moves at the destination)
    event_name_map = {
        "create": "file_created",
        "modify": "file_modified",
        "delete": "file_deleted",
        "move": "file_moved",
    }
    enabled_events = [
        event_name_map.get(event, event)
        for event, enabled in events.items()
        if enabled
    ]
    if enabled_events:
        rules.append(
            {
                "field": "event_subtype",
                "operator": "in",
                "value": enabled_events,
            }
        )

    if file_extensions:
        rules.append(
            {
                "field": "file_extension",
                "operator": "in",
                "value": file_extensions,
            }
        )

    conditions = {
        "match": "all",
        "rules": rules,
    }

    actions = {}
    if action == "quarantine" and quarantine_path:
        actions["quarantine"] = {"path": quarantine_path}
    elif action == "alert":
        actions["alert"] = {}
    else:
        # Default to block when unspecified/invalid
        actions["block"] = {}

    return conditions, actions


def _transform_google_drive_local_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Transform Google Drive local monitoring config to backend format

    Frontend format:
    {
        "basePath": "G:\\My Drive\\",  // Default: "G:\\My Drive\\"
        "monitoredFolders": ["Folder1", "Folder2/Subfolder"],
        "fileExtensions": [".pdf", ".docx"],  // Optional
        "events": {
            "create": true,
            "modify": true,
            "delete": false,
            "move": true
        },
        "action": "alert" | "quarantine" | "block" | "log",
        "quarantinePath": "C:\\Quarantine" (optional)
    }

    Backend format:
    conditions: {
        "match": "all",
        "rules": [
            {"field": "file_path", "operator": "matches_any_prefix", "value": ["G:\\Folder1", "G:\\Folder2\\Subfolder"]},
            {"field": "source", "operator": "equals", "value": "google_drive_local"},
            {"field": "event_subtype", "operator": "in", "value": ["file_created", "file_modified", ...]},
            {"field": "file_extension", "operator": "in", "value": [".pdf", ...]} (if specified)
        ]
    }
    actions: {
        "alert": {} | "quarantine": {"path": "..."} | "block": {} | "log": {}
    }
    """
    base_path = config.get("basePath", "G:\\My Drive\\")
    # Ensure base_path ends with backslash
    if not base_path.endswith("\\"):
        base_path = base_path + "\\"
    
    monitored_folders = config.get("monitoredFolders", [])
    file_extensions = config.get("fileExtensions", [])
    events = config.get("events", {})
    action = config.get("action", "log")
    quarantine_path = config.get("quarantinePath")

    rules = []

    # Build full paths from basePath + monitoredFolders
    full_paths = []
    if monitored_folders:
        for folder in monitored_folders:
            # Normalize folder path (remove leading/trailing slashes, normalize separators)
            folder = folder.strip().replace("/", "\\").strip("\\")
            if folder:
                full_path = base_path + folder
                # Ensure path ends with backslash for directory matching
                if not full_path.endswith("\\"):
                    full_path = full_path + "\\"
                full_paths.append(full_path)
    else:
        # If no folders specified, monitor entire base path
        full_paths.append(base_path)

    # Add path rules
    if full_paths:
        if len(full_paths) == 1:
            rules.append(
                {
                    "field": "file_path",
                    "operator": "starts_with",
                    "value": full_paths[0],
                }
            )
        else:
            rules.append(
                {
                    "field": "file_path",
                    "operator": "matches_any_prefix",
                    "value": full_paths,
                }
            )

    # Add source tag rule to identify Google Drive local events
    rules.append(
        {
            "field": "source",
            "operator": "equals",
            "value": "google_drive_local",
        }
    )

    # Add event type rules (copy is not supported for this legacy helper)
    event_name_map = {
        "create": "file_created",
        "modify": "file_modified",
        "delete": "file_deleted",
        "move": "file_moved",
    }
    enabled_events = [
        event_name_map.get(event, event)
        for event, enabled in events.items()
        if enabled
    ]
    if enabled_events:
        rules.append(
            {
                "field": "event_subtype",
                "operator": "in",
                "value": enabled_events,
            }
        )

    # Add file extension rules (if specified)
    if file_extensions:
        rules.append(
            {
                "field": "file_extension",
                "operator": "in",
                "value": file_extensions,
            }
        )

    # Build conditions
    conditions = {
        "match": "all",
        "rules": rules,
    }

    # Build actions
    actions = {}
    if action == "quarantine" and quarantine_path:
        actions["quarantine"] = {"path": quarantine_path}
    else:
        actions[action] = {}

    return conditions, actions
