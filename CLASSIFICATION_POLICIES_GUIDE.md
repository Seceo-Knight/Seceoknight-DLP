# Classification-Based Policy Guide

## Overview

The DLP system now supports **dynamic classification-based policies** that combine:
- **Rule-based content classification** (using 20+ pre-configured rules + custom rules)
- **Confidence-based scoring** (0.0 to 1.0)
- **Classification levels** (Public, Internal, Confidential, Restricted)
- **Policy conditions** that trigger actions based on classification results

This guide explains how to create policies that leverage the classification system.

---

## System Architecture

```
┌─────────────────┐
│  Agent Sends    │
│     Event       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ EventProcessor  │
│   validates,    │
│   normalizes,   │
│   enriches      │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│ ClassificationEngine    │
│ - Loads rules from DB   │
│ - Pattern matching      │
│ - Confidence scoring    │
│ - Classification level  │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Event with metadata:    │
│ - classification_level  │
│ - confidence_score      │
│ - matched_rules         │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ DatabasePolicyEvaluator │
│ - Evaluates conditions  │
│ - Classification fields │
│ - Numeric operators     │
└────────┬────────────────┘
         │
         ▼
┌─────────────────┐
│ Actions Execute │
│ - Block         │
│ - Alert         │
│ - Quarantine    │
└─────────────────┘
```

---

## Classification Levels

Based on confidence score (sum of matched rule weights):

| Confidence Score | Classification Level | Description                           |
|------------------|---------------------|---------------------------------------|
| 0.0 - 0.3        | **Public**          | No sensitive data detected            |
| 0.3 - 0.6        | **Internal**        | Low-sensitivity internal data         |
| 0.6 - 0.8        | **Confidential**    | Sensitive data requiring protection   |
| 0.8 - 1.0        | **Restricted**      | Highly sensitive data (PII, secrets)  |

---

## Available Policy Fields

### Classification Fields (NEW)

| Field                      | Type    | Description                                  | Example Values         |
|---------------------------|---------|----------------------------------------------|------------------------|
| `classification_level`     | string  | Classification result                        | "Restricted", "Public" |
| `confidence_score`         | float   | Confidence score (0.0 - 1.0)                | 0.95, 0.42             |
| `matched_rules_count`      | integer | Number of rules that matched                | 3, 0                   |
| `total_matches`            | integer | Total pattern matches across all rules      | 5, 12                  |
| `classification_engine`    | string  | Engine used ("rule_based")                  | "rule_based"           |

### Event Fields (Existing)

| Field               | Type   | Description                           |
|--------------------|--------|---------------------------------------|
| `event_type`       | string | Type of event                         |
| `event_subtype`    | string | Subtype of event                      |
| `severity`         | string | Event severity                        |
| `file_path`        | string | File path                             |
| `file_extension`   | string | File extension (.txt, .pdf)           |
| `destination_type` | string | Destination type                      |
| `source`           | string | Event source                          |

---

## Supported Operators

### String Operators
- `equals` - Exact match (case-insensitive)
- `contains` - Substring match
- `starts_with` - Prefix match
- `matches_regex` - Regular expression match
- `in` - Value in list

### Numeric Operators (NEW)
- `>=` or `greater_than_or_equal` - Greater than or equal
- `<=` or `less_than_or_equal` - Less than or equal
- `>` or `greater_than` - Greater than
- `<` or `less_than` - Less than

---

## Policy Examples

### Example 1: Block Restricted Data on Removable Drives

```json
{
  "name": "Block Restricted Data on USB",
  "description": "Prevent highly sensitive data from being copied to USB drives",
  "enabled": true,
  "priority": 100,
  "conditions": {
    "match": "all",
    "rules": [
      {
        "field": "classification_level",
        "operator": "equals",
        "value": "Restricted"
      },
      {
        "field": "destination_type",
        "operator": "equals",
        "value": "removable_drive"
      }
    ]
  },
  "actions": {
    "block": {
      "reason": "Restricted data cannot be copied to removable drives"
    },
    "alert": {
      "severity": "critical",
      "title": "Blocked: Restricted data to USB"
    }
  }
}
```

### Example 2: Alert on High-Confidence Clipboard Data

```json
{
  "name": "Alert on Sensitive Clipboard Content",
  "description": "Alert when clipboard contains highly sensitive data",
  "enabled": true,
  "priority": 80,
  "conditions": {
    "match": "all",
    "rules": [
      {
        "field": "confidence_score",
        "operator": ">=",
        "value": 0.8
      },
      {
        "field": "event_type",
        "operator": "equals",
        "value": "clipboard"
      }
    ]
  },
  "actions": {
    "alert": {
      "severity": "high",
      "title": "High-confidence sensitive data in clipboard",
      "message": "User copied sensitive data to clipboard"
    }
  }
}
```

### Example 3: Quarantine Confidential Files

```json
{
  "name": "Quarantine Confidential File Transfers",
  "description": "Quarantine files classified as Confidential or higher",
  "enabled": true,
  "priority": 90,
  "conditions": {
    "match": "all",
    "rules": [
      {
        "field": "classification_level",
        "operator": "in",
        "value": ["Confidential", "Restricted"]
      },
      {
        "field": "event_type",
        "operator": "equals",
        "value": "file"
      },
      {
        "field": "destination_type",
        "operator": "in",
        "value": ["email", "cloud_storage", "removable_drive"]
      }
    ]
  },
  "actions": {
    "quarantine": {
      "reason": "File contains confidential data"
    },
    "alert": {
      "severity": "high",
      "title": "File quarantined due to sensitive content"
    }
  }
}
```

### Example 4: Log Internal Data Transfers

```json
{
  "name": "Log Internal Data Transfers",
  "description": "Track transfers of internal-classified data for audit purposes",
  "enabled": true,
  "priority": 50,
  "conditions": {
    "match": "all",
    "rules": [
      {
        "field": "classification_level",
        "operator": "equals",
        "value": "Internal"
      },
      {
        "field": "event_type",
        "operator": "in",
        "value": ["file", "clipboard", "network"]
      }
    ]
  },
  "actions": {
    "log": {}
  }
}
```

### Example 5: Multi-Rule Match Threshold

```json
{
  "name": "Alert on Multiple Sensitive Patterns",
  "description": "Alert when 3 or more sensitive patterns are detected",
  "enabled": true,
  "priority": 85,
  "conditions": {
    "match": "all",
    "rules": [
      {
        "field": "matched_rules_count",
        "operator": ">=",
        "value": 3
      },
      {
        "field": "event_type",
        "operator": "equals",
        "value": "file"
      }
    ]
  },
  "actions": {
    "alert": {
      "severity": "high",
      "title": "Multiple sensitive patterns detected",
      "message": "File contains multiple types of sensitive data"
    }
  }
}
```

### Example 6: Graduated Response by Confidence

```json
{
  "name": "Graduated Response - Medium Confidence",
  "description": "Alert only for medium confidence scores",
  "enabled": true,
  "priority": 70,
  "conditions": {
    "match": "all",
    "rules": [
      {
        "field": "confidence_score",
        "operator": ">=",
        "value": 0.5
      },
      {
        "field": "confidence_score",
        "operator": "<",
        "value": 0.8
      }
    ]
  },
  "actions": {
    "alert": {
      "severity": "medium",
      "title": "Possible sensitive data detected"
    }
  }
}
```

---

## Policy Condition Logic

### Match Types

- **`all`**: ALL rules must match (AND logic)
- **`any`**: ANY rule must match (OR logic)
- **`none`**: NO rules must match (NOT logic)

### Nested Conditions

```json
{
  "conditions": {
    "match": "all",
    "rules": [
      {
        "field": "classification_level",
        "operator": "equals",
        "value": "Restricted"
      },
      {
        "match": "any",
        "rules": [
          {
            "field": "destination_type",
            "operator": "equals",
            "value": "removable_drive"
          },
          {
            "field": "destination_type",
            "operator": "equals",
            "value": "email"
          }
        ]
      }
    ]
  }
}
```

---

## Testing Policies

### 1. Create Test Rules

Navigate to **http://localhost:4000/rules** and create rules for testing:

```json
{
  "name": "Test SSN Detection",
  "type": "regex",
  "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
  "weight": 0.9,
  "severity": "critical",
  "category": "PII",
  "threshold": 1,
  "enabled": true
}
```

### 2. Test Classification

Use the **Test Rules** button on the Rules page:

```
Test Content:
My SSN is 123-45-6789
Credit Card: 4111-1111-1111-1111
```

Expected result:
- Classification: **Restricted**
- Confidence: **~0.95**
- Matched Rules: 2

### 3. Create Test Policy

```json
{
  "name": "Test Policy - Block Restricted",
  "conditions": {
    "match": "all",
    "rules": [
      {
        "field": "classification_level",
        "operator": "equals",
        "value": "Restricted"
      }
    ]
  },
  "actions": {
    "block": {},
    "alert": {
      "severity": "critical"
    }
  }
}
```

### 4. Send Test Event

From an agent or via API:

```bash
curl -X POST https://YOUR_SERVER_IP/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "test-001",
    "agent_id": "test-agent",
    "event_type": "clipboard",
    "content": "My SSN is 123-45-6789",
    "severity": "medium",
    "source_type": "clipboard"
  }'
```

Expected behavior:
- Event classified as **Restricted**
- Policy matches
- Event **blocked**
- Alert created

---

## Best Practices

### 1. Layered Policies

Create multiple policies with different priorities:

- **Priority 100**: Block critical threats (Restricted + removable drive)
- **Priority 80**: Alert on high-risk (Confidential + email)
- **Priority 60**: Log medium-risk (Internal + any destination)

### 2. Graduated Response

Use confidence thresholds for graduated responses:

- **≥ 0.9**: Block + Alert
- **0.7 - 0.9**: Quarantine + Alert
- **0.5 - 0.7**: Alert only
- **< 0.5**: Log only

### 3. Context-Aware Policies

Combine classification with context:

```json
{
  "match": "all",
  "rules": [
    {"field": "classification_level", "operator": "in", "value": ["Confidential", "Restricted"]},
    {"field": "file_extension", "operator": "in", "value": [".doc", ".pdf", ".xlsx"]},
    {"field": "destination_type", "operator": "equals", "value": "email"}
  ]
}
```

### 4. Rule Tuning

Monitor and adjust rule weights:

- High false positives → Reduce weight or increase threshold
- Missed detections → Increase weight or lower threshold
- Review **Rules Statistics** page for match counts

### 5. Performance Considerations

- Keep policies focused (3-5 conditions max)
- Use specific conditions (avoid broad regex in policies)
- Leverage caching (rules cached for 60s, policies for 30s)
- Monitor classification times in event metadata

---

## API Integration

### Get Classification for Content

```bash
POST /api/v1/rules/test
Content-Type: application/json
Authorization: Bearer <token>

{
  "content": "My SSN is 123-45-6789 and email is john@example.com"
}
```

Response:
```json
{
  "classification": "Restricted",
  "confidence_score": 0.95,
  "matched_rules": [
    {
      "rule_id": "uuid",
      "rule_name": "US Social Security Number",
      "rule_type": "regex",
      "match_count": 1,
      "weight": 0.9,
      "severity": "critical",
      "category": "PII"
    },
    {
      "rule_id": "uuid",
      "rule_name": "Email Address",
      "rule_type": "regex",
      "match_count": 1,
      "weight": 0.5,
      "severity": "medium",
      "category": "PII"
    }
  ],
  "total_matches": 2,
  "details": {
    "content_length": 58,
    "rules_evaluated": 20
  }
}
```

### Create Policy via API

```bash
POST /api/v1/policies
Content-Type: application/json
Authorization: Bearer <token>

{
  "name": "Block Restricted Data on USB",
  "description": "Prevent highly sensitive data transfers",
  "enabled": true,
  "priority": 100,
  "conditions": {
    "match": "all",
    "rules": [
      {"field": "classification_level", "operator": "equals", "value": "Restricted"},
      {"field": "destination_type", "operator": "equals", "value": "removable_drive"}
    ]
  },
  "actions": {
    "block": {},
    "alert": {"severity": "critical"}
  }
}
```

---

## Troubleshooting

### Policy Not Triggering

1. **Check rule status**: Ensure rules are enabled
2. **Check classification**: Test content in Rules page
3. **Check policy conditions**: Verify field names and operators
4. **Check policy priority**: Higher priority = evaluated first
5. **Check logs**: `docker compose logs manager -f`

### Low Confidence Scores

1. **Review matched rules**: Check which rules triggered
2. **Adjust weights**: Increase weights for important patterns
3. **Lower thresholds**: Reduce threshold for more sensitive detection
4. **Add more rules**: Create rules for missing patterns

### High False Positives

1. **Increase thresholds**: Require more matches before triggering
2. **Reduce weights**: Lower contribution to confidence score
3. **Refine patterns**: Make regex more specific
4. **Add context conditions**: Combine with file type, destination, etc.

### Performance Issues

1. **Check rule cache**: Should refresh every 60s
2. **Optimize regex**: Use efficient patterns
3. **Limit keywords**: Keep keyword lists focused
4. **Monitor event logs**: Check classification times

---

## Migration from Legacy Patterns

### Before (Hardcoded Patterns)

```python
# EventProcessor with hardcoded patterns
patterns = {
    "credit_card": {"pattern": r'\b(?:\d{4}[\s-]?){3}\d{4}\b', "severity": "critical"}
}
```

### After (Dynamic Rules)

```json
{
  "name": "Credit Card Number",
  "type": "regex",
  "pattern": "\\b(?:\\d{4}[\\s-]?){3}\\d{4}\\b",
  "weight": 0.95,
  "severity": "critical",
  "category": "Financial",
  "threshold": 1,
  "enabled": true
}
```

**Benefits**:
- No code changes needed to add/modify rules
- Per-rule weights for fine-tuned scoring
- Classification levels instead of binary detection
- UI for rule management and testing
- Statistics and match tracking

---

## Additional Resources

- **System Architecture**: `/CLASSIFICATION_SYSTEM.md`
- **Deployment Guide**: `/DEPLOYMENT_COMPLETE.md`
- **API Documentation**: https://YOUR_SERVER_IP/api/v1/docs
- **Rules Management**: http://localhost:4000/rules
- **Policies Management**: http://localhost:4000/policies

---

## Summary

The classification-based policy system provides:

✅ **Dynamic rule management** - Add/edit rules without code changes
✅ **Confidence-based scoring** - Weighted contributions from multiple rules
✅ **Classification levels** - Public, Internal, Confidential, Restricted
✅ **Policy conditions** - Use classification fields in policy rules
✅ **Numeric operators** - Compare confidence scores, match counts
✅ **Backward compatibility** - Legacy hardcoded patterns as fallback
✅ **Real-time testing** - Test rules and policies via UI
✅ **Performance optimized** - Rule and policy caching

Create sophisticated data protection policies that adapt to your organization's needs without touching code!
