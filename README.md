# 🛡️ Cybersecurity Automation Toolkit

![Languages](https://img.shields.io/github/languages/count/cardi83/Cybersecurity-Automation) ![Top Language](https://img.shields.io/github/languages/top/cardi83/Cybersecurity-Automation) ![Last Commit](https://img.shields.io/github/last-commit/cardi83/Cybersecurity-Automation)

A sampling of automation scripts and tools designed by Chris Cardi to streamline cybersecurity operations, improve visibility, and enhance security posture through repeatable, scalable processes.

## 📖 Overview

This repository includes real-world scripts and utilities built to:

- Automate repetitive security tasks
- Audit and validate configurations
- Tag and classify assets intelligently
- Integrate with tools like CrowdStrike, 1Password CLI, and system logs
- Generate reports and alerts for security findings

Each script is developed with modularity and reusability in mind, focusing on improving operational efficiency in an enterprise security environment.

---

## 📁 Contents

| Folder/File                    | Description                                                                                                        |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `crowdstrike_tag_audit.ps1`  | PowerShell script for identifying and tagging initial tester groups for definition rollout in CrowdStrike          |
| `op-bad-password-audit.ps1`  | Audit tool for detecting weak or temporary passwords in 1Password vaults                                           |
| `sentinel-threat-hunter.ps1` | PowerShell script for executing predefined threat hunting queries against Microsoft Sentinel and exporting results |
| `README.md`                  | This file                                                                                                          |

---

## 🛠️ Requirements

- PowerShell 7+
- [1Password CLI (`op`)](https://developer.1password.com/docs/cli/) for credential audits
- `ImportExcel` PowerShell module (for `.xlsx` export support)
- Administrative permissions (where needed)
- Optional (Recommended): VS Code with PowerShell or Python extension for editing

---
