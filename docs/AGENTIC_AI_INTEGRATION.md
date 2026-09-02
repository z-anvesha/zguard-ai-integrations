# AI Guard DAS in Agentic AI Architectures

## Overview

This document explains how AI Guard's Detection as a Service (DAS) pattern integrates with modern **Agentic AI** systems, where multiple autonomous agents collaborate to accomplish complex tasks.

## What is Agentic AI?

**Agentic AI** is an architecture pattern where:
- Multiple specialized AI agents work together
- Each agent has its own LLM and capabilities
- Agents communicate via **A2A** (Agent-to-Agent) protocol
- Agents access resources via **MCP** (Model Context Protocol)
- A **Coordinating Agent** orchestrates the workflow

### Agentic AI Architecture

```
                        ┌─────────────┐
                        │ Application │
                        └──────┬──────┘
                               │ NLP
                        ┌──────▼──────────────┐
                        │ Coordinating Agent  │
                        │  (Orchestrator)     │
                        └──────┬──────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
        ┌─────▼─────┐    ┌────▼────┐    ┌─────▼─────┐
        │  Agent 1  │    │ Agent 2 │    │  Agent 3  │
        │    LLM    │    │   LLM   │    │    LLM    │
        └─────┬─────┘    └────┬────┘    └─────┬─────┘
              │               │               │
              └───────┬───────┴───────┬───────┘
                      │ MCP Protocol  │
              ┌───────┴───────────────┴───────┐
              │                               │
    ┌─────────▼─────┐  ┌─────────┐  ┌───────▼───────┐
    │ Data Service  │  │  Code   │  │ Device Service│
    └───────────────┘  └─────────┘  └───────────────┘
```

**Key Characteristics:**
- **Multi-agent** - Multiple specialized agents
- **Distributed** - Each agent operates independently
- **Protocol-based** - A2A and MCP for communication
- **Service-oriented** - Agents consume MCP services

## Where AI Guard DAS Fits In

In an Agentic AI system, **each agent's interactions need protection**. AI Guard DAS provides security at **multiple integration points**:

### Integration Points Map

```
┌──────────────────────────────────────────────────────────────┐
│                    AI Guard DAS Protection                    │
│                                                               │
│  Application → [SCAN] → Coordinating Agent                   │
│                              ↓                                │
│                     [SCAN: A2A Messages]                      │
│                              ↓                                │
│         ┌────────────────────┼────────────────────┐          │
│         │                    │                    │          │
│   [SCAN]│              [SCAN]│              [SCAN]│          │
│         ↓                    ↓                    ↓          │
│   ┌─────────┐          ┌─────────┐          ┌─────────┐    │
│   │Agent 1  │          │Agent 2  │          │Agent 3  │    │
│   │  LLM    │          │  LLM    │          │  LLM    │    │
│   └────┬────┘          └────┬────┘          └────┬────┘    │
│        │ [SCAN: MCP]        │ [SCAN: MCP]        │          │
│        ↓                    ↓                    ↓          │
│   MCP Services      MCP Services       MCP Services         │
│        ↓                    ↓                    ↓          │
│   [SCAN: Response]    [SCAN: Response]    [SCAN: Response] │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

## AI Guard Protection Layers in Agentic AI

### Layer 1: Application → Coordinating Agent

**Protection Point:** User input to the coordinating agent

```
User: "Analyze our sales data and create a report"
   ↓
[AI Guard DAS - scan_user_input.py]
   ↓ SCAN: Prompt injection, toxicity, PII
   ↓
Coordinating Agent receives validated input
```

**Hook Type:** `UserPromptSubmit`  
**Direction:** `IN`  
**Protects Against:** Malicious instructions to the orchestrator

### Layer 2: Coordinating Agent → Sub-Agents (A2A)

**Protection Point:** Agent-to-agent communication

```
Coordinating Agent: "Agent 1, fetch customer data for Q4"
   ↓
[AI Guard DAS - scan_agent_message.py]
   ↓ SCAN: Command injection, unauthorized instructions
   ↓
Agent 1 receives validated task
```

**Protocol:** A2A (Agent-to-Agent)  
**Direction:** `IN` (to receiving agent)  
**Protects Against:** Malicious inter-agent communication

### Layer 3: Agent → MCP Services

**Protection Point:** Agent calling MCP tools/resources

```
Agent 2: Call mcp__database__query(sql="SELECT * FROM users")
   ↓
[AI Guard DAS - scan_mcp_request.py]
   ↓ SCAN: SQL injection, unauthorized queries
   ↓
MCP Service executes validated query
```

**Protocol:** MCP (Model Context Protocol)  
**Direction:** `IN` (to MCP service)  
**Protects Against:** 
- SQL injection
- Command injection
- Unauthorized resource access

### Layer 4: MCP Services → Agent

**Protection Point:** Service responses back to agents

```
MCP Service returns: {"users": [...customer data with PII...]}
   ↓
[AI Guard DAS - scan_response.py]
   ↓ SCAN: PII, secrets, data leakage
   ↓
Agent 2 receives sanitized response
```

**Protocol:** MCP Response  
**Direction:** `OUT` (from service)  
**Protects Against:**
- PII in responses
- Secrets exposure
- Data exfiltration

### Layer 5: Agent → LLM

**Protection Point:** Agent's prompt to its LLM

```
Agent 3: Send prompt to LLM with aggregated data
   ↓
[AI Guard DAS - scan_llm_prompt.py]
   ↓ SCAN: Ensure no sensitive data in LLM prompt
   ↓
LLM processes validated prompt
```

**Direction:** `OUT` (to external LLM)  
**Protects Against:** Sending sensitive data to LLM providers

## Why DAS is Perfect for Agentic AI

### Problem: Distributed Multi-Agent Systems

```
Challenge:
- Multiple agents, each making independent decisions
- Each agent calling different services
- Agent-to-agent communication
- Multiple LLM providers potentially
- Complex data flows

Proxy Approach Would Require:
❌ All agents route through central proxy
❌ Proxy understands A2A protocol
❌ Proxy tracks multi-agent state
❌ Single point of failure for entire system
❌ Complex proxy logic for orchestration
```

### Solution: DAS Pattern ✅

```
AI Guard DAS Provides:
✅ Each agent integrates independently
✅ Protection at each interaction point
✅ No coordination required between agents
✅ No single point of failure
✅ Scales with number of agents
✅ Protocol-agnostic (works with A2A, MCP, custom)
```

## Implementation in Agentic AI

### Example: Multi-Agent System with AI Guard

```python
# Coordinating Agent
class CoordinatingAgent:
    def __init__(self):
        self.aiguard = AIGuardClient()  # DAS client
        self.agents = [Agent1(), Agent2(), Agent3()]
    
    def process_user_request(self, user_input: str):
        # LAYER 1: Scan user input
        if not self.aiguard.scan(user_input, direction="IN"):
            return "Request blocked by security policy"
        
        # Orchestrate agents
        tasks = self.plan_tasks(user_input)
        results = []
        
        for agent, task in zip(self.agents, tasks):
            # LAYER 2: Scan A2A message
            if self.aiguard.scan(task, direction="IN"):
                result = agent.execute(task)
                results.append(result)
        
        return self.aggregate_results(results)


# Individual Agent
class DataAgent:
    def __init__(self):
        self.aiguard = AIGuardClient()  # DAS client
        self.mcp_client = MCPClient()
    
    def execute(self, task: str):
        # Parse task and determine MCP service to call
        service, params = self.parse_task(task)
        
        # LAYER 3: Scan MCP request
        if not self.aiguard.scan(params, direction="IN"):
            return {"error": "MCP request blocked"}
        
        # Call MCP service
        response = self.mcp_client.call_tool(service, params)
        
        # LAYER 4: Scan MCP response
        if not self.aiguard.scan(response, direction="OUT"):
            return {"error": "MCP response blocked"}
        
        # LAYER 5: Send to LLM for processing
        llm_prompt = self.create_llm_prompt(response)
        
        if not self.aiguard.scan(llm_prompt, direction="OUT"):
            return {"error": "LLM prompt blocked"}
        
        return self.llm.generate(llm_prompt)
```

## Real-World Agentic AI Scenario

### Scenario: Enterprise Data Analysis System

```
User Request: "Analyze Q4 sales and generate recommendations"

┌────────────────────────────────────────────────────────────┐
│ COORDINATING AGENT                                         │
│ [✓] User prompt scanned by AI Guard DAS                   │
│ Decision: Delegate to 3 specialized agents                 │
└────────────┬──────────────┬──────────────┬────────────────┘
             │              │              │
   ┌─────────▼────┐  ┌─────▼─────┐  ┌────▼──────────┐
   │ Data Agent   │  │ Analytics │  │ Report Agent  │
   │              │  │ Agent     │  │               │
   │ [✓] A2A msg  │  │ [✓] A2A   │  │ [✓] A2A msg   │
   │ scanned      │  │ msg       │  │ scanned       │
   └──────┬───────┘  └─────┬─────┘  └────┬──────────┘
          │                │              │
          │ MCP Call       │ MCP Call     │ MCP Call
          ↓                ↓              ↓
   ┌──────────────┐  ┌─────────────┐  ┌─────────────┐
   │ [✓] Scan MCP │  │ [✓] Scan    │  │ [✓] Scan    │
   │ Database     │  │ Analytics   │  │ Document    │
   │ query params │  │ function    │  │ generation  │
   └──────┬───────┘  └─────┬───────┘  └────┬────────┘
          │                │              │
          ↓ Execute        ↓ Execute     ↓ Execute
   ┌──────────────┐  ┌─────────────┐  ┌─────────────┐
   │ SQL Database │  │ Python Code │  │ Doc Service │
   └──────┬───────┘  └─────┬───────┘  └────┬────────┘
          │                │              │
          ↓ Response       ↓ Response    ↓ Response
   ┌──────────────┐  ┌─────────────┐  ┌─────────────┐
   │ [✓] Scan for │  │ [✓] Scan    │  │ [✓] Scan    │
   │ PII/secrets  │  │ results     │  │ document    │
   │ BLOCK if PII │  │             │  │             │
   └──────────────┘  └─────────────┘  └─────────────┘
```

**AI Guard DAS scans at each step:**
- Initial user request
- A2A messages between coordinating agent and sub-agents
- MCP tool calls from each agent
- Responses from each MCP service
- Final aggregated output

## MCP in Agentic AI: Your Current Implementation

### Your Zscaler MCP Server in Agentic Context

```
┌──────────────────────────────────────────────────────────┐
│              Agentic AI System                           │
│                                                          │
│  Agent 1 (Security)  → Needs ZPA/ZIA data               │
│  Agent 2 (Compliance)→ Needs audit logs                 │
│  Agent 3 (Ops)       → Needs device status              │
│                                                          │
│  All agents use MCP protocol to access:                 │
│     ↓                                                    │
│  ┌──────────────────────────────────────────┐           │
│  │    Zscaler MCP Server (Docker)           │           │
│  │  - zpa_list_applications                 │           │
│  │  - zia_list_firewall_rules              │           │
│  │  - zcc_list_devices                     │           │
│  └─────────────┬────────────────────────────┘           │
│                ↓                                         │
│         [AI Guard DAS Protection]                       │
│                ↓                                         │
│  Each agent's call is scanned independently             │
└──────────────────────────────────────────────────────────┘
```

**Your Current Claude Code Setup:**
- Claude Code = One agent in a potential agentic system
- Your hooks = DAS protection for that agent's MCP calls
- Zscaler MCP Server = One of many possible MCP services

**Expansion to Multi-Agent:**
```
Agent 1 (Claude Code)     → [✓] Protected by hooks
Agent 2 (Cursor)          → [✓] Can add same DAS protection
Agent 3 (Custom Python)   → [✓] Can add DAS SDK integration
   ↓                          ↓                        ↓
All agents → Zscaler MCP Server
           → Protected at each layer
```

## Benefits of DAS in Agentic AI

### Scalability

```
Traditional Proxy:
1 Proxy handling (Agent1 + Agent2 + Agent3 + ... + AgentN) calls
= Bottleneck at proxy

DAS:
Each agent independently calls AI Guard API
= Scales linearly with agents
```

### Resilience

```
Traditional Proxy:
Proxy fails → All agents blocked
= System-wide failure

DAS:
One agent's AI Guard call fails → Only that agent affected
= Isolated failures
```

### Flexibility

```
Traditional Proxy:
All agents must use same proxy endpoint
= Tight coupling

DAS:
Agent 1 → AI Guard US1
Agent 2 → AI Guard EU1
Agent 3 → Custom policy
= Flexible per-agent configuration
```

## Implementation Roadmap for Agentic AI

### Phase 1: Single Agent Protection ✅ (Complete)
- Claude Code with hooks
- MCP request/response scanning
- User input validation

### Phase 2: Multi-Agent Expansion
```python
# Example: Add DAS to LangChain agents

from langchain.agents import Agent
from aiguard import AIGuardCallback

class SecureAgent(Agent):
    def __init__(self):
        super().__init__()
        self.add_callback(AIGuardCallback(
            # Omit the policy id so the API resolves the policy bound to
            # your key; a stale id fails closed on every request.
            scan_prompts=True,
            scan_tools=True,
            scan_responses=True
        ))

# Each agent gets its own DAS protection
security_agent = SecureAgent()
data_agent = SecureAgent()
reporting_agent = SecureAgent()
```

### Phase 3: A2A Communication Protection
```python
# Scan agent-to-agent messages

class CoordinatingAgent:
    def send_to_agent(self, agent_id: str, message: dict):
        # Scan A2A message
        if not self.aiguard.scan(
            content=json.dumps(message),
            direction="IN",
            context="a2a_communication"
        ):
            raise SecurityError("A2A message blocked")
        
        return self.agents[agent_id].receive(message)
```

### Phase 4: Orchestrator-Level Protection
```python
# Coordinating agent with comprehensive scanning

class SecureCoordinator:
    def orchestrate(self, user_input: str):
        # Scan user input
        self.aiguard.scan(user_input, direction="IN")
        
        # Plan agent tasks
        plan = self.create_plan(user_input)
        
        # Scan each agent task before delegation
        for task in plan:
            self.aiguard.scan(task.message, direction="IN")
            agent = self.get_agent(task.agent_id)
            
            # Agent executes with its own DAS protection
            result = agent.execute(task)
        
        # Scan aggregated results
        final_output = self.aggregate(results)
        self.aiguard.scan(final_output, direction="OUT")
        
        return final_output
```

## Key Differences: Single Agent vs Agentic AI

| Aspect | Single Agent (Current) | Agentic AI (Future) |
|--------|----------------------|-------------------|
| **Agents** | 1 (Claude Code) | Multiple (Coordinator + Specialists) |
| **Communication** | User ↔ Agent | User → Coordinator → Agents (A2A) |
| **MCP Usage** | 1 agent calls MCP | Multiple agents call MCP services |
| **AI Guard Integration** | Hooks in Claude Code | DAS in each agent + coordinator |
| **Scan Points** | 3 layers (input, mcp, response) | 5+ layers (input, a2a, mcp, response, llm) |
| **Complexity** | Low | High (multi-agent coordination) |

## Summary

Your **DAS implementation is perfectly positioned** for Agentic AI architectures:

### Current State (Single Agent):
```
Claude Code → [DAS Protection] → Zscaler MCP Server
```

### Future State (Agentic AI):
```
                  Coordinating Agent
                    [DAS Protection]
                          ↓
        ┌─────────────────┼─────────────────┐
        ↓                 ↓                 ↓
   Agent 1          Agent 2          Agent 3
[DAS Protection] [DAS Protection] [DAS Protection]
        ↓                 ↓                 ↓
      MCP Services (Zscaler, GitHub, Database, etc.)
```

**Key Points:**
1. ✅ Your DAS pattern is the **right architecture** for agentic AI
2. ✅ Each agent can integrate AI Guard **independently**
3. ✅ Scales naturally with **number of agents**
4. ✅ Protection at **every interaction point**
5. ✅ No central proxy required
6. ✅ **MCP protocol** is already designed for this

The Agentic AI slide shows exactly why **Detection as a Service (DAS)** is the modern approach - distributed agents need distributed security, not a centralized bottleneck!
