Project 1: API-Sentinel - Runtime BOLA & Shadow API Detection Engine

Project Overview

API-Sentinel is an advanced API Security project focused on protecting modern applications from unauthorized access and hidden API risks. The main goal is to monitor API traffic in real time, discover undocumented APIs, detect authorization attacks such as BOLA (Broken Object Level Authorization), and provide a security dashboard for monitoring threats. 
In this project, we will use eBPF and Rust to capture API traffic at the Linux kernel level, Python for traffic analysis and attack detection, and React for building a monitoring dashboard. 

Why This Project?

Modern applications rely heavily on APIs. Traditional security tools often fail to detect business logic attacks such as BOLA and cannot identify undocumented or "Shadow APIs". This project addresses those challenges using a Zero-Trust security approach. 

Main Objectives

* Monitor API traffic in real time using eBPF. 
* Create an inventory of all active API endpoints. 
* Detect undocumented or Shadow APIs. 
* Detect BOLA and BFLA authorization attacks. 
* Block malicious API requests. 
* Build a dashboard to visualize threats and vulnerabilities. 
Technologies Used

* Rust
* eBPF
* Python
* React
* OpenAPI / Swagger Specifications
* OWASP API Security Top 10 Framework 
Key Modules
1. Kernel-Level Sniffer
Captures API traffic directly from the Linux kernel using eBPF and Rust. 
2. Shadow API Discovery Engine
Compares live API traffic with official API documentation and identifies undocumented APIs. 
3. Behavioral Authorization Engine
Analyzes user behavior and detects unauthorized access attempts such as BOLA and BFLA attacks. 
4. Threat Dashboard
Displays detected threats, vulnerable APIs, API inventory, and OWASP API Top 10 mappings. 
Week-wise Plan
Week 1
* Capture API traffic using eBPF.
* Build a Python parser to reconstruct API requests and responses.
Week 2
* Generate API inventory automatically.
* Implement Shadow API detection.
* Develop BOLA detection logic.
Mid Review
* Demonstrate traffic monitoring.
* Simulate and detect a BOLA attack.
* Verify system performance.
Week 3
* Add active blocking capability.
* Implement rate limiting and bot detection. 
Week 4
* Implement data masking for sensitive information.
* Finalize the threat dashboard and OWASP mapping. 

External Concepts We Need to Learn

BOLA (Broken Object Level Authorization)
A vulnerability where a user can access another user's data by changing object IDs because authorization checks are missing. 

BFLA (Broken Function Level Authorization)
A vulnerability where users can access functions or actions that should only be available to higher-privileged users. 

eBPF
A Linux kernel technology used for monitoring, tracing, and analyzing system/network activity with minimal performance impact. 

Shadow APIs
APIs that exist in production but are not documented in official API specifications. 

OpenAPI / Swagger
Industry-standard API documentation formats used for defining and documenting APIs. 

OWASP API Security Top 10
A globally recognized security standard that lists the most critical API security risks. 

Zero-Trust Architecture
A security model that assumes no user or system is trusted by default and every request must be verified. 
Final Deliverables

By the end of the project, we should have:

✅ Real-time API traffic monitoring system
 ✅ Shadow API detection engine
 ✅ BOLA/BFLA attack detection system
 ✅ API inventory generation
 ✅ Threat monitoring dashboard
 ✅ Active API attack blocking capability 

Axlero Requirements

* Project duration: 4 weeks.
* GitHub is mandatory. 
* Mid Review checks Week 1 and Week 2 work.
* Final Review checks Week 3 and Week 4 work.
* Team repository must have regular commits. 
* Each team member should work on their assigned tasks and contribute through GitHub.

This project is mainly about = API Security, eBPF, Rust, Python, OWASP API Security Top 10, Zero-Trust Architecture, Threat Detection, and Security Monitorin

