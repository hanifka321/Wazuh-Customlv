# Non-Technical Intake Template

This document helps analysts, managers, or customers describe what they need from the UEBA platform without using engineering jargon. Hand the completed template to a technical owner so they can translate it into mappings, rules, and dashboards.

---

## How to Use This Template

1. **Talk through each section out loud** with the requester. Keep the language in their words.
2. **Fill in the blanks** directly in this file or copy/paste the sections into an email or ticket.
3. **Attach real log samples** (screenshots, CSV, JSON, etc.) if available.
4. **Send the completed form** to the UEBA/automation team. They will map every answer to specific configurations.

> ⚠️ Only include sensitive data (IP ranges, usernames) if the communication channel is approved for that data.

---

## Prompt Format (Copy/Paste Friendly)

```
### 1. Contact Info & Context
- Business owner / SME:
- Team / Department:
- Preferred contact method (email, chat, phone):
- Deadline or event driving this request:

### 2. Data to Monitor
- Source system(s): (e.g., Wazuh agents, Windows DCs, VPN logs)
- Where the data lives today:
- Retention needs (how long should we keep it?):

### 3. Fields That Matter
- Unique thing(s) we track (hostnames, usernames, IP addresses, account IDs):
- Fields that prove identity (agent ID, user ID, etc.):
- Fields that describe severity or priority:
- Extra context we want to keep (location, business unit, ticket number):

### 4. Behaviors to Flag
- Normal behavior definition (what "good" looks like):
- Suspicious behavior definition (what "bad" looks like):
- Volume/threshold ideas (e.g., "more than 5 failures in 10 minutes"):
- Business impact if we miss it:

### 5. Desired Outcomes
- What should happen when we detect it? (alert, ticket, dashboard widget, email):
- Who needs to be notified:
- How quickly we need to respond:

### 6. Supplemental Notes
- Existing dashboards, reports, or tickets we can reuse:
- Known false positives we should avoid:
- Any compliance/audit requirements tied to this monitoring:
```

---

## Example 1 – Privileged Login Monitoring

```
1. Contact Info & Context
   - Owner: Jane Doe (Security Operations)
   - Contact: jane@example.com / #soc-alerts channel
   - Deadline: Before quarterly compliance audit (Mar 15)

2. Data to Monitor
   - Source systems: Wazuh agents on Linux jump hosts, Windows Domain Controllers
   - Storage: Already flowing into central Wazuh manager
   - Retention: 180 days

3. Fields That Matter
   - Tracking: user names, source IPs, hostnames
   - Identity fields: `agent.id` for hosts, `data.user.name` for users
   - Severity: `rule.level` where >= 8 should feel urgent
   - Extra context: geolocation, business unit of the server

4. Behaviors to Flag
   - Normal: Admins log in from corporate VPN during business hours
   - Suspicious: Any admin login outside 06:00-22:00 UTC or from non-corporate IPs
   - Threshold: >3 failed logins from the same IP within 15 minutes
   - Impact: High. Could indicate account takeover

5. Desired Outcomes
   - Action: Create a high-priority alert in the dashboard and open a Jira ticket
   - Audience: SOC Tier 2 on-call
   - Response time: 15 minutes

6. Supplemental Notes
   - False positives: Developers often log in during release weekends (whitelist their jump boxes)
   - Compliance: Tied to SOX quarterly control 12.3
```

## Example 2 – VPN License Abuse (Short Form)

```
- Team: IT Networking
- Data: Prisma VPN logs exported as JSON
- Fields we care about: username, assigned license tier, session length
- Suspicious behavior: Single user consuming more than 12 hours of concurrent VPN time (license sharing)
- Outcome: Email IT licensing team with a CSV of offenders each Monday
```

---

## Sharing Best Practices

- Keep the original wording. Engineers will map it to YAML selectors or Python code later.
- If you are unsure about a field name, describe it (“the column that shows the laptop name”) and attach a sample.
- Revisit the intake form once the feature ships. Confirm the monitoring output matches the plain-language expectations, then iterate together if not.

Use this template anytime you need to capture requirements from someone who doesn’t want to read code. It ensures nothing is lost between the business ask and the technical implementation.
