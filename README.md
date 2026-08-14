# Aegis Architecture & Compliance Engine (AACE)

Active multi-account AWS security, compliance, and governance engine designed to audit, control, viabilize, and automate cloud posture based on international frameworks.

## 🚀 Key Capabilities
* **Multi-Account Discovery & Orchestration:** Automatically maps and executes parallel audits across enterprise AWS environments.
* **Multi-Pillar Auditing:** Specialized modules for WAF & Network security, IAM compliance/drift, S3 storage protection, encryption, and logging.
* **Standards Alignment:** Evaluates infrastructure directly against NIST CSF, CIS Benchmarks, and the AWS Well-Architected Framework.
* **Active Control & Remediation:** Goes beyond reporting by generating actionable risk matrices, automated remediation templates, and centralized compliance dashboards.

## 🛠️ Project Structure
* `orchestrator.js` - Main parallel execution engine.
* `*_audit.js` - Specialized security pillar modules (WAF, IAM, S3, ECS, etc.).
* `knowledge_base/` - Reference security policies and compliance frameworks.
* `templates/` - Remediation guidelines and security baseline check templates.
