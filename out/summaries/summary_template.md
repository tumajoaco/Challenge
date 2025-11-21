# Incident {{ incident.incident_id }}

## Asset
- Device ID: {{ incident.asset.device_id }}
- Hostname: {{ incident.asset.hostname }}
- IP: {{ incident.asset.ip }}

## Indicators
| Type | Value | Veredict | Score |
|------|-------|----------|-------|
{% for ind in incident.indicators %}
| {{ ind.type }} | {{ ind.value }} | {{ ind.risk.veredict }} | {{ ind.risk.score }} |
{% endfor %}

## Severity
- Severity: {{ incident.triage.severity }}
- Bucket: {{ incident.triage.bucket }}

## Tags
- Tags: {{ incident.triage.tags | join(', ') }}


##MITRE ATT&CK techniques
- Techniques: {{ incident.mitre.techniques | join(', ') }}

##Actions Taken
| Type | Target | Result | TimeStamp |
|------|--------|--------|-----------|
{% for act in incident.actions %}
| {{ act.type }} | {{ act.target }} | {{ act.result }} | {{ act.ts }} |
{% endfor %}

##Timeline
| Stage | TimeStamp | Details |
|-------|-----------|---------|
{% for ts in incident.timeline %}
| {{ ts.stage }} | {{ ts.ts }} | {{ ts.details }} |
{% endfor %}