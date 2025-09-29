"""
Sample data generator for security controls and threat intelligence
"""

from datetime import datetime, timedelta
from typing import List
import uuid

from models.security_models import (
    SecurityControl, ThreatIntelligence, Architecture, ThreatControlRelationship,
    ControlType, ThreatCategory, SeverityLevel
)


def generate_sample_security_controls() -> List[SecurityControl]:
    """Generate sample security controls"""
    
    controls = [
        SecurityControl(
            id="ctrl_001",
            name="Multi-Factor Authentication (MFA)",
            description="Implement multi-factor authentication for all user accounts to prevent unauthorized access even if credentials are compromised.",
            control_type=ControlType.PREVENTIVE,
            framework="NIST",
            control_id="AC-2",
            implementation_guidance="Deploy MFA using TOTP, SMS, or hardware tokens. Require MFA for all administrative accounts and sensitive operations.",
            effectiveness_rating=0.9,
            cost_rating=0.3,
            complexity_rating=0.4,
            applicable_threats=[ThreatCategory.BROKEN_AUTH, ThreatCategory.BROKEN_ACCESS],
            applicable_architectures=["web_app", "api", "microservices"],
            tags=["authentication", "access_control", "identity"]
        ),
        SecurityControl(
            id="ctrl_002",
            name="Input Validation and Sanitization",
            description="Implement comprehensive input validation and sanitization to prevent injection attacks.",
            control_type=ControlType.PREVENTIVE,
            framework="OWASP",
            control_id="V5.1",
            implementation_guidance="Validate all input data using whitelisting approach. Sanitize data before processing. Use parameterized queries for database operations.",
            effectiveness_rating=0.85,
            cost_rating=0.5,
            complexity_rating=0.6,
            applicable_threats=[ThreatCategory.INJECTION, ThreatCategory.XSS],
            applicable_architectures=["web_app", "api"],
            tags=["input_validation", "injection_prevention", "data_sanitization"]
        ),
        SecurityControl(
            id="ctrl_003",
            name="Web Application Firewall (WAF)",
            description="Deploy a Web Application Firewall to filter, monitor, and block HTTP traffic to and from web applications.",
            control_type=ControlType.PREVENTIVE,
            framework="CIS",
            control_id="CIS-6.1",
            implementation_guidance="Configure WAF rules to block common attack patterns. Enable logging and monitoring for security events.",
            effectiveness_rating=0.75,
            cost_rating=0.6,
            complexity_rating=0.5,
            applicable_threats=[ThreatCategory.INJECTION, ThreatCategory.XSS, ThreatCategory.BROKEN_ACCESS],
            applicable_architectures=["web_app", "api"],
            tags=["firewall", "traffic_filtering", "attack_prevention"]
        ),
        SecurityControl(
            id="ctrl_004",
            name="Security Headers Implementation",
            description="Implement security headers to protect against common web vulnerabilities.",
            control_type=ControlType.PREVENTIVE,
            framework="OWASP",
            control_id="V14.4",
            implementation_guidance="Implement CSP, HSTS, X-Frame-Options, X-XSS-Protection, and other security headers.",
            effectiveness_rating=0.7,
            cost_rating=0.2,
            complexity_rating=0.3,
            applicable_threats=[ThreatCategory.XSS, ThreatCategory.SECURITY_MISCONFIG],
            applicable_architectures=["web_app"],
            tags=["headers", "xss_prevention", "clickjacking_prevention"]
        ),
        SecurityControl(
            id="ctrl_005",
            name="API Rate Limiting",
            description="Implement rate limiting to prevent abuse and DoS attacks on API endpoints.",
            control_type=ControlType.PREVENTIVE,
            framework="NIST",
            control_id="SC-5",
            implementation_guidance="Configure rate limits based on user roles and endpoint sensitivity. Implement progressive penalties for violations.",
            effectiveness_rating=0.8,
            cost_rating=0.4,
            complexity_rating=0.4,
            applicable_threats=[ThreatCategory.BROKEN_ACCESS],
            applicable_architectures=["api", "microservices"],
            tags=["rate_limiting", "dos_prevention", "api_security"]
        ),
        SecurityControl(
            id="ctrl_006",
            name="Encryption at Rest",
            description="Encrypt sensitive data stored in databases and file systems.",
            control_type=ControlType.PREVENTIVE,
            framework="ISO27001",
            control_id="A.10.1.1",
            implementation_guidance="Use AES-256 encryption for data at rest. Implement proper key management and rotation policies.",
            effectiveness_rating=0.9,
            cost_rating=0.7,
            complexity_rating=0.7,
            applicable_threats=[ThreatCategory.SENSITIVE_DATA],
            applicable_architectures=["web_app", "api", "microservices"],
            tags=["encryption", "data_protection", "key_management"]
        ),
        SecurityControl(
            id="ctrl_007",
            name="Security Logging and Monitoring",
            description="Implement comprehensive security logging and monitoring for threat detection.",
            control_type=ControlType.DETECTIVE,
            framework="NIST",
            control_id="AU-2",
            implementation_guidance="Log all security-relevant events. Implement real-time monitoring and alerting for suspicious activities.",
            effectiveness_rating=0.8,
            cost_rating=0.6,
            complexity_rating=0.6,
            applicable_threats=[ThreatCategory.INSUFFICIENT_LOGGING, ThreatCategory.BROKEN_ACCESS],
            applicable_architectures=["web_app", "api", "microservices"],
            tags=["logging", "monitoring", "incident_detection"]
        ),
        SecurityControl(
            id="ctrl_008",
            name="Service Mesh Security",
            description="Implement service mesh with mTLS for secure microservices communication.",
            control_type=ControlType.PREVENTIVE,
            framework="NIST",
            control_id="SC-8",
            implementation_guidance="Deploy Istio or similar service mesh with automatic mTLS. Implement service-to-service authentication and authorization.",
            effectiveness_rating=0.85,
            cost_rating=0.8,
            complexity_rating=0.8,
            applicable_threats=[ThreatCategory.BROKEN_AUTH, ThreatCategory.SENSITIVE_DATA],
            applicable_architectures=["microservices"],
            tags=["service_mesh", "mtls", "microservices_security"]
        )
    ]
    
    return controls


def generate_sample_threat_intelligence() -> List[ThreatIntelligence]:
    """Generate sample threat intelligence data"""
    
    threats = [
        ThreatIntelligence(
            id="threat_001",
            name="SQL Injection Attack",
            description="Malicious SQL code injection through user input to manipulate database queries and gain unauthorized access to data.",
            threat_category=ThreatCategory.INJECTION,
            severity=SeverityLevel.HIGH,
            attack_vectors=["Form inputs", "URL parameters", "HTTP headers", "API endpoints"],
            affected_components=["Web applications", "Database servers", "API endpoints"],
            indicators_of_compromise=["Unusual database queries", "Error messages revealing database structure", "Unexpected data access patterns"],
            mitigation_strategies=["Input validation", "Parameterized queries", "Least privilege database access", "WAF deployment"],
            cve_references=["CVE-2021-44228", "CVE-2020-1472"],
            mitre_attack_techniques=["T1190", "T1078"],
            likelihood_score=0.8,
            impact_score=0.9,
            exploitability_score=0.7,
            applicable_architectures=["web_app", "api"],
            tags=["injection", "database", "web_security"],
            first_seen=datetime.utcnow() - timedelta(days=30),
            last_updated=datetime.utcnow()
        ),
        ThreatIntelligence(
            id="threat_002",
            name="Cross-Site Scripting (XSS)",
            description="Injection of malicious scripts into web pages viewed by other users, leading to session hijacking and data theft.",
            threat_category=ThreatCategory.XSS,
            severity=SeverityLevel.MEDIUM,
            attack_vectors=["User input fields", "URL parameters", "File uploads", "Stored content"],
            affected_components=["Web browsers", "Web applications", "User sessions"],
            indicators_of_compromise=["Unusual JavaScript execution", "Unexpected redirects", "Session token theft"],
            mitigation_strategies=["Input sanitization", "Output encoding", "CSP headers", "XSS filters"],
            cve_references=["CVE-2021-44228"],
            mitre_attack_techniques=["T1059", "T1185"],
            likelihood_score=0.7,
            impact_score=0.6,
            exploitability_score=0.8,
            applicable_architectures=["web_app"],
            tags=["xss", "web_security", "client_side"],
            first_seen=datetime.utcnow() - timedelta(days=45),
            last_updated=datetime.utcnow()
        ),
        ThreatIntelligence(
            id="threat_003",
            name="Broken Authentication",
            description="Vulnerabilities in authentication mechanisms allowing attackers to compromise passwords, keys, or session tokens.",
            threat_category=ThreatCategory.BROKEN_AUTH,
            severity=SeverityLevel.CRITICAL,
            attack_vectors=["Credential stuffing", "Brute force attacks", "Session hijacking", "Password spraying"],
            affected_components=["Authentication systems", "Session management", "User accounts"],
            indicators_of_compromise=["Multiple failed login attempts", "Unusual login patterns", "Session anomalies"],
            mitigation_strategies=["Multi-factor authentication", "Strong password policies", "Account lockout", "Session management"],
            cve_references=["CVE-2021-34527", "CVE-2020-1472"],
            mitre_attack_techniques=["T1110", "T1078", "T1550"],
            likelihood_score=0.9,
            impact_score=0.95,
            exploitability_score=0.8,
            applicable_architectures=["web_app", "api", "microservices"],
            tags=["authentication", "credential_theft", "session_security"],
            first_seen=datetime.utcnow() - timedelta(days=60),
            last_updated=datetime.utcnow()
        ),
        ThreatIntelligence(
            id="threat_004",
            name="API Security Misconfiguration",
            description="Improperly configured API security settings leading to unauthorized access and data exposure.",
            threat_category=ThreatCategory.SECURITY_MISCONFIG,
            severity=SeverityLevel.HIGH,
            attack_vectors=["Unprotected endpoints", "Missing authentication", "Excessive permissions", "Default configurations"],
            affected_components=["API gateways", "REST endpoints", "Authentication services"],
            indicators_of_compromise=["Unauthorized API calls", "Data exfiltration", "Privilege escalation"],
            mitigation_strategies=["API security testing", "Proper configuration management", "Regular security assessments", "Least privilege access"],
            cve_references=["CVE-2021-26855"],
            mitre_attack_techniques=["T1190", "T1078"],
            likelihood_score=0.75,
            impact_score=0.8,
            exploitability_score=0.6,
            applicable_architectures=["api", "microservices"],
            tags=["api_security", "misconfiguration", "access_control"],
            first_seen=datetime.utcnow() - timedelta(days=20),
            last_updated=datetime.utcnow()
        ),
        ThreatIntelligence(
            id="threat_005",
            name="Microservices Communication Interception",
            description="Man-in-the-middle attacks on unencrypted communication between microservices.",
            threat_category=ThreatCategory.SENSITIVE_DATA,
            severity=SeverityLevel.HIGH,
            attack_vectors=["Network sniffing", "Traffic interception", "Service impersonation"],
            affected_components=["Service-to-service communication", "Internal networks", "Message queues"],
            indicators_of_compromise=["Unusual network traffic", "Service authentication failures", "Data integrity issues"],
            mitigation_strategies=["mTLS implementation", "Service mesh deployment", "Network segmentation", "Certificate management"],
            cve_references=["CVE-2021-44228"],
            mitre_attack_techniques=["T1040", "T1557"],
            likelihood_score=0.6,
            impact_score=0.85,
            exploitability_score=0.5,
            applicable_architectures=["microservices"],
            tags=["microservices", "communication_security", "encryption"],
            first_seen=datetime.utcnow() - timedelta(days=15),
            last_updated=datetime.utcnow()
        ),
        ThreatIntelligence(
            id="threat_006",
            name="Insufficient Logging and Monitoring",
            description="Lack of adequate logging and monitoring allows attacks to go undetected for extended periods.",
            threat_category=ThreatCategory.INSUFFICIENT_LOGGING,
            severity=SeverityLevel.MEDIUM,
            attack_vectors=["Stealth attacks", "Gradual data exfiltration", "Privilege escalation"],
            affected_components=["Logging systems", "Monitoring infrastructure", "SIEM platforms"],
            indicators_of_compromise=["Missing audit logs", "Delayed incident detection", "Unaccounted system changes"],
            mitigation_strategies=["Comprehensive logging implementation", "Real-time monitoring", "Security information and event management (SIEM)", "Automated alerting"],
            cve_references=[],
            mitre_attack_techniques=["T1070", "T1562"],
            likelihood_score=0.8,
            impact_score=0.7,
            exploitability_score=0.4,
            applicable_architectures=["web_app", "api", "microservices"],
            tags=["logging", "monitoring", "detection"],
            first_seen=datetime.utcnow() - timedelta(days=40),
            last_updated=datetime.utcnow()
        )
    ]
    
    return threats


def generate_sample_architectures() -> List[Architecture]:
    """Generate sample architecture definitions"""
    
    architectures = [
        Architecture(
            id="arch_001",
            name="Three-Tier Web Application",
            description="Traditional three-tier web application with presentation, business logic, and data layers.",
            components=["Web server", "Application server", "Database server", "Load balancer"],
            data_flows=["Client to web server", "Web server to app server", "App server to database"],
            trust_boundaries=["Internet to DMZ", "DMZ to internal network", "Application to database"],
            threat_model="STRIDE",
            compliance_requirements=["PCI-DSS", "GDPR"],
            tags=["web_app", "three_tier", "traditional"]
        ),
        Architecture(
            id="arch_002",
            name="RESTful API Architecture",
            description="RESTful API-based architecture with microservices and API gateway.",
            components=["API Gateway", "Authentication service", "Business services", "Database cluster"],
            data_flows=["Client to API gateway", "Gateway to services", "Services to databases"],
            trust_boundaries=["External to API gateway", "Gateway to services", "Services to data"],
            threat_model="PASTA",
            compliance_requirements=["OWASP API Security", "OAuth 2.0"],
            tags=["api", "rest", "microservices"]
        ),
        Architecture(
            id="arch_003",
            name="Microservices with Service Mesh",
            description="Cloud-native microservices architecture with service mesh for communication.",
            components=["Service mesh", "Container orchestrator", "Microservices", "Message brokers", "Distributed databases"],
            data_flows=["External to ingress", "Service mesh routing", "Inter-service communication"],
            trust_boundaries=["External to cluster", "Service mesh boundaries", "Namespace isolation"],
            threat_model="LINDDUN",
            compliance_requirements=["Cloud security frameworks", "Container security"],
            tags=["microservices", "cloud_native", "service_mesh"]
        )
    ]
    
    return architectures


def generate_sample_relationships() -> List[ThreatControlRelationship]:
    """Generate sample threat-control relationships"""
    
    relationships = [
        ThreatControlRelationship(
            threat_id="threat_001",
            control_id="ctrl_002",
            effectiveness=0.9,
            coverage_percentage=0.85,
            implementation_cost="medium",
            relationship_type="prevents"
        ),
        ThreatControlRelationship(
            threat_id="threat_001",
            control_id="ctrl_003",
            effectiveness=0.75,
            coverage_percentage=0.7,
            implementation_cost="high",
            relationship_type="detects"
        ),
        ThreatControlRelationship(
            threat_id="threat_002",
            control_id="ctrl_004",
            effectiveness=0.8,
            coverage_percentage=0.6,
            implementation_cost="low",
            relationship_type="prevents"
        ),
        ThreatControlRelationship(
            threat_id="threat_003",
            control_id="ctrl_001",
            effectiveness=0.95,
            coverage_percentage=0.9,
            implementation_cost="medium",
            relationship_type="prevents"
        ),
        ThreatControlRelationship(
            threat_id="threat_004",
            control_id="ctrl_005",
            effectiveness=0.8,
            coverage_percentage=0.75,
            implementation_cost="medium",
            relationship_type="mitigates"
        ),
        ThreatControlRelationship(
            threat_id="threat_005",
            control_id="ctrl_008",
            effectiveness=0.9,
            coverage_percentage=0.95,
            implementation_cost="high",
            relationship_type="prevents"
        ),
        ThreatControlRelationship(
            threat_id="threat_006",
            control_id="ctrl_007",
            effectiveness=0.85,
            coverage_percentage=0.8,
            implementation_cost="medium",
            relationship_type="detects"
        )
    ]
    
    return relationships