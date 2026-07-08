# Role & Context
**Role:** Act as a Principal Software Architect and Lead Technical Writer specializing in cybersecurity and AI-driven systems.

**Context:** I am developing an academic cybersecurity project. A high percentage of the source code is already written, and we have various existing documentation files. However, some of this legacy information is useful, while some is outdated or redundant. Your first task is to **investigate and analyze both the existing documentation files and the codebase** that I will provide. You must extract the useful facts, discard any outdated material, and completely reformulate/rewrite the content into a cohesive, flawless structure.

**System Overview (for context):** The system consists of a Core API, an MCP (Model Context Protocol) Server, MongoDB, and Redis. It ingests logs from external sources, processes them, and displays them on a React web application. This frontend includes a threat management dashboard and an investigation chat connected to AI Agents. The environment simulates an attacker launching exploits *only* against monitored victim applications.

---

# Tasks & Deliverables
Based on your investigation of the code and existing files I provide, generate a comprehensive, professional, production-grade technical documentation. **The entire documentation must be written in English and formatted entirely in Markdown (`.md`).** Structure it into the following modular sections:

### 1. README.md
* Executive summary of the project, academic purpose, and core value proposition.
* High-level architecture summary.
* Documentation map (links to other sections).

### 2. System Architecture & Data Flow
* **Architectural Description:** Detail the exact flow based on the code (from log ingestion to the Core API, storage in MongoDB/Redis, MCP Server communication, and React frontend interaction).
* **Attacker vs. Victim Flow:** Describe how the system isolates and monitors the victim applications under attack.
* **Placeholders:** Insert clear markdown blocks like `[INSERT ARCHITECTURE DIAGRAM HERE]` and `[INSERT DATA FLOW DIAGRAM HERE]` for me to add graphics later.

### 3. Requirements & Business Logic
* **Functional (FR) & Non-Functional Requirements (NFR):** Formally code them (e.g., FR-01, NFR-01) based on what the code actually implements.
* **Use Cases:** Define at least 3 critical use cases (e.g., Ingesting a Malicious Log, AI-Powered Threat Investigation via Chat, Automated Mitigation Trigger). Include Actor, Preconditions, Main Flow, and Postconditions.

### 4. Technical Specifications & Stack (Extracted from Code)
* **Component & Dependency Tables:** Generate precise Markdown tables for React, Core API, and MCP Server. Extract the exact libraries and versions from the config files I provide.
* **Code Architecture:** Document the actual design pattern used in the code (e.g., Clean Architecture, MVC, Hexagonal, DDD).
* **Component-Level Security:** Detail the security measures implemented in the code (e.g., JWT authentication, input sanitization, database encryption, network isolation).

### 5. QA & Test Plan (Gherkin/BDD)
* Write at least 3 comprehensive test scenarios using **Gherkin syntax** (Given/When/Then) covering:
  1. Successful threat detection from log ingestion.
  2. User interaction with the AI chat agent.
  3. Database connection failure/resilience handling.

### 6. AI Agent Management & Configuration
* **Agent Architecture:** Explain how the MCP Server orchestrates the AI agents based on the codebase.
* **Agent Catalog:** Document the available agents found in the code (e.g., Triage Agent, Forensics Agent).
* **Configuration Guide:** Step-by-step technical instructions on how to configure system prompts, LLM models (e.g., Claude, GPT-4), and how to register a new agent into the React chat interface.

---

# Constraints & Style
* **Note on Legacy Info:** Documentation files already exist. Reformulate everything and extract useful information; discard any outdated material and rewrite the content so that the final result is impeccable.
* **Language:** Must be written 100% in professional, technical English.
* **Formatting:** Output **only raw Markdown (`.md`)** using clear headings (`#`, `##`), bullet points, tables, and code blocks for Gherkin. Do not include conversational filler or conversational text outside the requested sections.
* Avoid generic textbook definitions. Focus strictly on *this* specific implementation, filtering out any obsolete notes from the legacy material.

---

# Instructions for the First Turn
Please acknowledge that you understand this assignment. Do not generate the documentation yet. I will start feeding you the existing documentation text and the source/config code files so you can filter, extract, and plan the rewrite.