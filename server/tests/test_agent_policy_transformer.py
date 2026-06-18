import types

from app.policies.agent_policy_transformer import AgentPolicyTransformer


def make_policy(
    *,
    policy_id: str,
    name: str,
    policy_type: str,
    enabled: bool = True,
    priority: int = 100,
    severity: str = "medium",
    config: dict | None = None,
    actions: dict | None = None,
    agent_ids: list[str] | None = None,
):
    return types.SimpleNamespace(
        id=policy_id,
        name=name,
        type=policy_type,
        enabled=enabled,
        priority=priority,
        severity=severity,
        config=config or {},
        actions=actions or {},
        compliance_tags=[],
        updated_at=None,
        created_at=None,
        agent_ids=agent_ids or [],
    )


def test_windows_bundle_includes_supported_policies():
    transformer = AgentPolicyTransformer()
    policies = [
        make_policy(
            policy_id="p-clipboard",
            name="Clipboard Policy",
            policy_type="clipboard_monitoring",
            config={"monitoredPaths": [], "action": "alert"},
        ),
        make_policy(
            policy_id="p-files",
            name="Files Policy",
            policy_type="file_system_monitoring",
            config={"monitoredPaths": ["C:/Sensitive"], "action": "alert"},
        ),
        make_policy(
            policy_id="p-transfer",
            name="Transfer Policy",
            policy_type="file_transfer_monitoring",
            config={
                "protectedPaths": ["C:/Sensitive"],
                "monitoredDestinations": ["D:/Staging"],
                "action": "block",
            },
        ),
        make_policy(
            policy_id="p-usb",
            name="USB Policy",
            policy_type="usb_file_transfer_monitoring",
            config={"monitoredPaths": ["C:/Sensitive"], "action": "block"},
        ),
    ]

    bundle = transformer.build_bundle(policies, platform="windows")

    assert bundle["policies"]["clipboard_monitoring"]
    assert bundle["policies"]["file_system_monitoring"]
    assert bundle["policies"]["file_transfer_monitoring"]
    assert bundle["policies"]["usb_file_transfer_monitoring"]


def test_linux_bundle_filters_platform():
    transformer = AgentPolicyTransformer()
    policies = [
        make_policy(
            policy_id="p-clipboard",
            name="Clipboard Policy",
            policy_type="clipboard_monitoring",
            config={"monitoredPaths": [], "action": "alert"},
        ),
        make_policy(
            policy_id="p-files",
            name="Files Policy",
            policy_type="file_system_monitoring",
            config={"monitoredPaths": ["/opt/data"], "action": "alert"},
        ),
    ]

    bundle = transformer.build_bundle(policies, platform="linux")

    assert "clipboard_monitoring" not in bundle["policies"]
    assert bundle["policies"]["file_system_monitoring"][0]["config"]["monitoredPaths"] == ["/opt/data"]


def test_version_changes_when_policy_changes():
    transformer = AgentPolicyTransformer()
    policy = make_policy(
        policy_id="p-files",
        name="Files Policy",
        policy_type="file_system_monitoring",
        config={"monitoredPaths": ["C:/Docs"], "action": "alert"},
    )

    bundle_v1 = transformer.build_bundle([policy], platform="windows")
    policy.config["monitoredPaths"].append("C:/Secret")
    bundle_v2 = transformer.build_bundle([policy], platform="windows")

    assert bundle_v1["version"] != bundle_v2["version"]


def test_agent_scoped_policy_included_only_for_matching_agent():
    transformer = AgentPolicyTransformer()
    scoped_policy = make_policy(
        policy_id="p-agent",
        name="Agent Scoped Policy",
        policy_type="file_system_monitoring",
        config={"monitoredPaths": ["C:/Docs"], "action": "alert"},
        agent_ids=["agent-123"],
    )
    global_policy = make_policy(
        policy_id="p-global",
        name="Global Policy",
        policy_type="file_system_monitoring",
        config={"monitoredPaths": ["C:/Global"], "action": "alert"},
    )

    bundle_for_agent = transformer.build_bundle([scoped_policy, global_policy], platform="windows", agent_id="agent-123")
    bundle_other_agent = transformer.build_bundle([scoped_policy, global_policy], platform="windows", agent_id="agent-999")

    included_paths = [p["config"]["monitoredPaths"][0] for p in bundle_for_agent["policies"]["file_system_monitoring"]]
    assert "C:/Docs" in included_paths
    assert "C:/Global" in included_paths

    other_paths = [p["config"]["monitoredPaths"][0] for p in bundle_other_agent["policies"]["file_system_monitoring"]]
    assert "C:/Docs" not in other_paths
    assert "C:/Global" in other_paths


def test_agent_scoped_policy_excluded_for_non_matching_agent():
    transformer = AgentPolicyTransformer()
    scoped_policy = make_policy(
        policy_id="p-agent-only",
        name="Agent Only",
        policy_type="file_system_monitoring",
        config={"monitoredPaths": ["C:/Docs"], "action": "alert"},
        agent_ids=["agent-abc"],
    )

    bundle = transformer.build_bundle([scoped_policy], platform="windows", agent_id="agent-xyz")

    assert "file_system_monitoring" not in bundle["policies"]


def test_version_changes_when_agent_scope_changes():
    transformer = AgentPolicyTransformer()
    policy = make_policy(
        policy_id="p-scope",
        name="Scoped Policy",
        policy_type="file_system_monitoring",
        config={"monitoredPaths": ["C:/Docs"], "action": "alert"},
        agent_ids=["agent-1"],
    )

    bundle_v1 = transformer.build_bundle([policy], platform="windows", agent_id="agent-1")
    policy.agent_ids.append("agent-2")
    bundle_v2 = transformer.build_bundle([policy], platform="windows", agent_id="agent-1")

    assert bundle_v1["version"] != bundle_v2["version"]


def test_bundle_preserves_quarantine_action_and_path():
    transformer = AgentPolicyTransformer()
    policy = make_policy(
        policy_id="p-transfer",
        name="Transfer Quarantine Policy",
        policy_type="file_transfer_monitoring",
        config={
            "protectedPaths": ["/opt/data"],
            "monitoredDestinations": ["/mnt/staging"],
            "action": "quarantine",
            "quarantinePath": "/quarantine",
        },
    )

    bundle = transformer.build_bundle([policy], platform="linux")

    serialized = bundle["policies"]["file_transfer_monitoring"][0]["config"]
    assert serialized["action"] == "quarantine"
    assert serialized["quarantinePath"] == "/quarantine"


