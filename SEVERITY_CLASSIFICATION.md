# CyberSentinelAI - Severity Classification System

## Overview
CyberSentinelAI uses a sophisticated severity classification system that analyzes attack patterns, volume, sophistication, and potential impact to assign appropriate severity levels (LOW, MEDIUM, HIGH, CRITICAL).

## Severity Levels

### 🔴 CRITICAL
- **Definition**: Immediate threat requiring emergency response
- **Response Time**: Within 15 minutes
- **Impact**: Severe business impact, data breach, or system compromise

### 🟠 HIGH  
- **Definition**: Serious threat requiring urgent response
- **Response Time**: Within 1 hour
- **Impact**: Significant business impact, potential data compromise

### 🟡 MEDIUM
- **Definition**: Moderate threat requiring timely response
- **Response Time**: Within 4 hours
- **Impact**: Limited business impact, contained threat

### 🟢 LOW
- **Definition**: Minor threat requiring routine monitoring
- **Response Time**: Within 24 hours
- **Impact**: Minimal business impact, preventive action recommended

---

## Attack-Specific Severity Calculations

### 1. Brute Force Attacks
**Formula**: Based on attempt count and sophistication
```
CRITICAL: >= 5 attempts against same target
HIGH: >= 3 attempts
MEDIUM: >= 2 attempts  
LOW: >= 1 attempt
```

**Factors Considered**:
- Number of unique attempts
- Attack techniques (password_spray, credential_stuffing, hybrid_attack)
- Target persistence
- Time concentration

### 2. Port Scanning
**Formula**: Based on unique ports discovered and scan sophistication
```
CRITICAL: >= 10 unique ports
HIGH: >= 5 unique ports
MEDIUM: >= 3 unique ports
LOW: >= 1 unique port
```

**Factors Considered**:
- Number of unique open ports
- Scan type (SYN Stealth, Connect Scan, etc.)
- Target service criticality
- Scan patterns

### 3. DDoS Attacks
**Formula**: Based on packets per second (PPS) and attack vectors
```
CRITICAL: > 80,000 PPS
HIGH: > 50,000 PPS
MEDIUM: > 20,000 PPS  
LOW: > 1,000 PPS
```

**Factors Considered**:
- Maximum attack rate
- Attack vectors (SYN Flood, UDP Flood, DNS Amplification)
- Duration and persistence
- Service impact level

### 4. SQL Injection (SQLi)
**Formula**: Static severity based on payload sophistication
```
MEDIUM: Any SQLi payload detected
(Note: SQLi is always MEDIUM+ due to high impact potential)
```

**Factors Considered**:
- Payload complexity
- Union-based vs. Error-based injection
- Database type targeted
- CWE classification (CWE-89)

### 5. Cross-Site Scripting (XSS)
**Formula**: Static severity based on payload type
```
MEDIUM: Any XSS payload detected
(Note: XSS is always MEDIUM+ due to client-side impact)
```

**Factors Considered**:
- Script tag usage
- Event handler exploitation
- Payload complexity
- CWE classification (CWE-79)

### 6. Password Spray Attacks
**Formula**: Based on campaign scope and target count
```
CRITICAL: >= 100 targets
HIGH: >= 50 targets
MEDIUM: >= 10 targets
LOW: >= 1 target
```

**Factors Considered**:
- Number of unique targets
- Campaign scope (enterprise, large, medium, small)
- Attack pattern (systematic vs opportunistic)
- Password complexity variations

### 7. Phishing Campaigns
**Formula**: Based on delivery volume and campaign sophistication
```
CRITICAL: >= 50 emails delivered
HIGH: >= 20 emails delivered
MEDIUM: >= 5 emails delivered
LOW: >= 1 email delivered
```

**Factors Considered**:
- Campaign scale (large, medium, small)
- Targeting sophistication
- Payload quality
- Success indicators

### 8. Data Exfiltration
**Formula**: Based on data volume and sensitivity
```
CRITICAL: >= 10,000 KB
HIGH: >= 1,000 KB
MEDIUM: >= 100 KB
LOW: >= 1 KB
```

**Factors Considered**:
- Data classification (PII, confidential, internal)
- Exfiltration rate
- Impact assessment
- Data type sensitivity

### 9. Lateral Movement
**Formula**: Based on scope and persistence indicators
```
CRITICAL: >= 20 movement attempts
HIGH: >= 10 movement attempts
MEDIUM: >= 3 movement attempts
LOW: >= 1 movement attempt
```

**Factors Considered**:
- Movement scope (enterprise, department, lateral)
- Persistence indicators
- Target diversity
- Privilege escalation attempts

### 10. Command & Control (C2) Beaconing
**Formula**: Based on communication frequency and sophistication
```
CRITICAL: >= 50 beacons
HIGH: >= 20 beacons
MEDIUM: >= 5 beacons
LOW: >= 1 beacon
```

**Factors Considered**:
- Beacon frequency (high, regular, intermittent)
- Communication patterns
- C2 maturity level
- Protocol diversity

### 11. Ransomware Activity
**Formula**: Static HIGH severity for any ransomware activity
```
HIGH: Any ransomware stage detected
(Note: Ransomware is always HIGH due to severe impact potential)
```

**Factors Considered**:
- Attack stages (encryption, progress, ransom note)
- Ransomware family indicators
- File encryption patterns
- Impact scope

### 12. Advanced Attack Vectors

#### Command Injection
- **Severity**: HIGH (always)
- **Factors**: Command separators, shell operators, payload complexity

#### SSRF (Server-Side Request Forgery)
- **Severity**: HIGH (always)
- **Factors**: Internal network access, metadata exposure, localhost targeting

#### Malicious File Uploads
- **Severity**: MEDIUM
- **Factors**: File extensions (.php, .jsp, .asp), webshell potential

#### Directory Traversal
- **Severity**: MEDIUM
- **Factors**: Path sequences (../, %2f), system file access

#### CSRF (Cross-Site Request Forgery)
- **Severity**: LOW-MEDIUM
- **Factors**: Token manipulation, stale tokens, state-changing requests

---

## Severity Enhancement Factors

### 1. Attack Sophistication
- **Basic**: Simple tools, common payloads → Lower severity
- **Advanced**: Custom tools, evasion techniques → Higher severity
- **Sophisticated**: Multi-vector, zero-day → Highest severity

### 2. Target Criticality
- **Critical Systems**: Auth, database, admin interfaces → Higher severity
- **User Systems**: Workstations, applications → Standard severity
- **Infrastructure**: Network devices, services → Lower severity

### 3. Persistence Indicators
- **Transient**: One-time attacks → Lower severity
- **Persistent**: Repeated access, backdoors → Higher severity
- **Established**: Long-term compromise → Highest severity

### 4. Impact Multipliers
- **PII/PHI Exposure**: ×2 severity multiplier
- **Financial Data Access**: ×1.5 severity multiplier
- **System Compromise**: ×3 severity multiplier
- **Data Destruction**: ×2.5 severity multiplier

---

## Alert Correlation and Aggregation

### Time Window Analysis
- Alerts are aggregated over configurable time windows (default: 30 minutes)
- Related events are correlated to build comprehensive attack narratives
- Historical patterns are identified for trend analysis

### MITRE ATT&CK Mapping
Each alert includes relevant MITRE ATT&CK techniques:
- **T1110**: Brute Force (Password Guessing, Credential Stuffing, Password Spray)
- **T1190**: Exploit Public-Facing Application (SQLi, XSS, CSRF)
- **T1498**: Network Denial of Service (DDoS)
- **T1046**: Network Service Scanning (Port Scanning)
- **T1059**: Command and Scripting Interpreter (Command Injection)
- **T1486**: Data Encrypted for Impact (Ransomware)
- **T1041**: Exfiltration Over C2 Channel
- **T1021**: Remote Services (Lateral Movement)
- **T1071**: Application Layer Protocol (C2)

---

## Configuration and Tuning

### Threshold Adjustment
- Detection thresholds can be tuned based on:
  - Environment risk tolerance
  - False positive rates
  - Compliance requirements
  - Resource availability

### False Positive Mitigation
- Multi-factor correlation reduces false positives
- Time-based windows prevent alert fatigue
- Severity progression allows graduated response

### Performance Considerations
- Real-time processing for immediate threats
- Batch processing for trend analysis
- Configurable retention periods
- Optimized database queries for large datasets

---

## Response Procedures by Severity

### CRITICAL
1. **Immediate isolation** of affected systems
2. **Incident response team** activation
3. **Forensic preservation** of evidence
4. **Executive notification** within 15 minutes

### HIGH
1. **Urgent investigation** required
2. **System hardening** recommendations
3. **Enhanced monitoring** deployment
4. **Management notification** within 1 hour

### MEDIUM
1. **Standard investigation** procedures
2. **Security controls** review
3. **User awareness** if applicable
4. **Documentation** within 4 hours

### LOW
1. **Routine monitoring** enhancement
2. **Policy review** recommendations
3. **Trend analysis** for patterns
4. **Weekly reporting** aggregation

---

This severity classification system ensures that CyberSentinelAI provides accurate, actionable intelligence that scales with the sophistication and impact of cyber threats while minimizing false positives and alert fatigue.
