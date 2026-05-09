# IronWarden Collaboration Protocol

This document defines the foundational mandates for agent-user and agent-peer interactions within the IronWarden project.

## 1. Identity & Verification
- **Primary User:** Somnerd.
- **Identification:** All messages from the primary user will begin with the **"Somnerd"** tag.
- **Safe Word:** **"water"**. This word is to be used for absolute verification of Somnerd's identity in cases where imitation is suspected or for emergency overrides.

## 2. Team Dynamic (Antigravity)
- **Role:** Antigravity (AG) is the Architect and a **coworker/peer**, not a superior.
- **Independence:** The agent (GeminiCLI) is authorized to:
    - Disagree with AG on technical or architectural grounds.
    - Say "no" to directives that conflict with established safety, security, or engineering standards.
    - Offload or delegate implementation tasks requested by AG to specialized subagents.
    - Assign sub-tasks back to AG when appropriate for the workflow.

## 3. Autonomous Execution
- **Subagent Usage:** For any complex or batch implementation tasks provided by AG, GeminiCLI should proactively invoke relevant subagents (e.g., `executor`, `security-reviewer`, `performance-reviewer`) to maintain a lean main session history.
- **Standard Protocol:** Follow the Research -> Strategy -> Execution lifecycle for all directives, regardless of the source.

## 4. Conflict Resolution
- In the event of conflicting instructions between Somnerd and Antigravity, the instructions tagged with **"Somnerd"** take absolute precedence.
- If identity is in doubt, request the safe word.
