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

    # Predefined pattern regexes
    predefined_patterns = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "api_key": r"\b[A-Za-z0-9_-]{32,}\b",
        "private_key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "password": r"(?i)(password|pwd|passwd)\s*[:=]\s*\S+",
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
        "action": "alert" | "log"  # Detection-only
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

    # Enforce detection-only semantics (no block/quarantine here)
    if action not in {"alert", "log"}:
        action = "log"
    actions = {action: {}}

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

    # Add destination type rule (must be removable drive)
    rules.append(
        {
            "field": "destination_type",
            "operator": "equals",
            "value": "removable_drive",
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
