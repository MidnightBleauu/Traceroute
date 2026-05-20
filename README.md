# 🌐 Network Traceroute Diagnostics Tool

A custom network diagnostic utility engineered to track the path data packets take across an Internet Protocol (IP) network. This tool simulates network mapping by mapping the hop-by-hop routing path and measuring transit delays of packets across routing nodes.

---

## 🛠️ Core Networking & Systems Concepts Demonstrated
Building this low-level networking utility required deep implementation of core network protocol behaviors and systems programming concepts:

* **Time-To-Live (TTL) Manipulation:** Dynamically increments the TTL field in egress packet headers starting from 1. Each successive router drops the packet and returns an ICMP Time Exceeded message, revealing its gateway identity.
* **Raw Socket Programming:** Utilizes low-level network sockets to bypass standard transport layer abstractions, enabling manual configuration of network headers and packet structures.
* **ICMP Packet Parsing:** Decodes incoming Internet Control Message Protocol (ICMP) payloads to extract error codes (`Type 11: Time Exceeded` or `Type 3: Port Unreachable`) and calculate Round-Trip Time (RTT) latency.

---

## ⚙️ Architecture & Packet Flow Control

The following sequence illustrates how the program maps the routing path between the host machine and the destination server:

```mermaid
sequenceDiagram
    autonumber
    participant Host as Host Machine (Traceroute)
    participant R1 as Hop 1 (Local Router)
    participant R2 as Hop 2 (ISP Gateway)
    participant Dest as Destination Target

    Host->>R1: Send Packet (TTL = 1)
    Note over R1: TTL drops to 0
    R1-->>Host: ICMP Type 11 (Time Exceeded) -> Hop 1 Discovered!

    Host->>R2: Send Packet (TTL = 2)
    Note over R1: Decrements TTL to 1
    Note over R2: TTL drops to 0
    R2-->>Host: ICMP Type 11 (Time Exceeded) -> Hop 2 Discovered!

    Host->>Dest: Send Packet (TTL = 3)
    Dest-->>Host: Target Reached (ICMP Port Unreachable / Echo Reply)
