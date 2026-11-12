# 🛡️ API-Sentinel

> **Real-time API Security Engine**  
> We monitor live API traffic without slowing down apps, spot hidden APIs, and catch sneaky authorization attacks like BOLA before damage is done.

---

## 🧐 What is this project?

Almost every modern app runs on APIs. When you order food, check your bank balance, or send a message, your phone talks to a server through APIs.

Most security tools (like Web Application Firewalls) look for obvious attacks, like someone typing weird SQL code into a search box. But modern API attacks don't look like that:

1. **BOLA (Broken Object Level Authorization):**  
   Imagine you log in and view your receipt at `/api/orders/1001`. Then you change the URL number to `/api/orders/1002`. If the app gives you someone else's receipt, that's BOLA! Standard firewalls can't spot this because the request looks 100% normal.
2. **Shadow APIs (Hidden Endpoints):**  
   Developers often build quick test routes or forget to delete old versions (like `/v1/debug_users`). These don't appear in the official documentation, so security teams don't even know they exist.

**API-Sentinel** is our solution. We watch network traffic quietly right inside the Linux kernel using **eBPF** (so developers don't have to change a single line of code). We rebuild that traffic, figure out who is calling what, check if they actually own the data, and block attackers on the fly.

---

## ⚙️ How Traffic Flows Through the System

Here is the simple, step-by-step path traffic takes:

```text
       [ API Users & Microservices ]
                     │
  ─── KERNEL SPACE ──┼────────────────────────────────────────────────
                     ▼
            eBPF Kernel Probes      <-- Listens to socket calls (send/recv)
                     │
                Ring Buffer
  ─── USER SPACE ────┼────────────────────────────────────────────────
                     ▼
             Rust Agent (sensor/)   <-- Pulls raw bytes out of the kernel
                     │
                     ▼ (Raw byte fragments)
          HTTP Parser (parser/)     <-- [Prince's Module]
          • Glues fragments back into HTTP requests & responses
          • Reads JWT tokens or API keys to identify the user
          • Measures how long the call took (latency)
                     │
                     ▼ (Clean, structured records)
          ┌──────────┴──────────┐
          ▼                     ▼
    Shadow API Engine     BOLA / BFLA Engine
    (Agam - discovery/)   (Hariom - detector/)
    Finds undocumented    Spots users stealing other
    endpoints and bots.   people's data or admin rights.
          │                     │
          └──────────┬──────────┘
                     ▼
              PII Masker (Meet - masking/)
              Hides sensitive info (passwords, emails)
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
    React Dashboard       Kernel Blocklist
    (Meet - dashboard/)   (Pranav - sensor/)
    Shows live alerts     Drops attacker packets
    and endpoint maps.    instantly at network level.
```

---

## 👥 Who is Building What?

We are a 5-person team working on this project as part of our Axlero Solutions cybersecurity internship:

| Teammate | Folder | What They Own | Tech Stack |
|:---|:---|:---|:---|
| **Pranav** | `sensor/` | **Kernel Sniffer:** Writes eBPF programs in C/Rust to grab traffic without adding delay, and drops blocked IPs with XDP. | Rust, eBPF, Aya |
| **Prince** *(Me)* | `parser/` | **HTTP Parser:** Takes messy raw byte chunks, reassembles full HTTP requests/responses, identifies the user from JWTs, and measures latency. | Python |
| **Agam** | `discovery/`, `ratelimit/` | **Shadow API & Rate Limiting:** Discovers unlisted endpoints, checks them against OpenAPI specs, and stops spammers/bots. | Python |
| **Hariom** | `detector/` | **BOLA & BFLA Detection:** Tracks which user owns what ID, flags when someone touches someone else's data, and triggers blocks. | Python |
| **Meet** | `masking/`, `dashboard/`, `testbed/` | **UI, Privacy & Testbed:** Masks sensitive user data, builds the React frontend, and runs test attacks against crAPI. | React, Vite, Docker |

---

## 🧩 Deep Dive: My Module (`parser/`)

My job is the bridge between the kernel and the security brains.

When the kernel grabs network packets, they arrive in raw, broken chunks. My parser:
1. **Reassembles Streams:** Buffers TCP data so that partial packets get stitched together into complete HTTP requests and responses.
2. **Matches Pairs:** Connects each request to its matching response so we know the status code (like 200 OK or 403 Forbidden) and the exact round-trip time (`latency_ms`).
3. **Pulls Identity:** Inspects `Authorization: Bearer <JWT>` tokens or API keys to see *who* is making the request (e.g. `user_55`) and what *role* they have (`admin` vs `user`).
4. **Sends Clean Records:** Emits a simple Python object (`Record`) that Agam and Hariom can analyze immediately.

### What the output record looks like:
```json
{
  "ts": 1731312000.1,
  "user": "user_55",
  "role": "user",
  "method": "GET",
  "path": "/api/orders/1002",
  "status": 200,
  "req_body": null,
  "resp_body": {"id": 1002, "item": "Keyboard"},
  "latency_ms": 12.4,
  "src_ip": "10.0.0.7"
}
```

---

## 📅 4-Week Schedule

### **Week 1 — Getting the Basics Working**
- [x] **Day 1:** Set up repo, clean modular design, defined data contracts (`Record`, `RawFragment`), built identity extractor, wrote 17 unit tests.
- [ ] **Day 2:** Parse HTTP request lines and headers (handle JSON bodies and content lengths).
- [ ] **Day 3:** Parse HTTP responses and status codes.
- [ ] **Day 4:** Match requests and responses together per connection and calculate latency.
- [ ] **Day 5:** Handle tricky edge cases (broken packets, weird headers, huge bodies).
- [ ] **Day 6:** Test with realistic fake traffic dumps.
- [ ] **Day 7:** Clean up code, fix any bugs, and get ready for Week 2.

### **Week 2 — Finding Attacks & Mid Review**
- Map all discovered API endpoints automatically.
- Flag shadow APIs not found in the OpenAPI docs.
- Detect BOLA attacks when IDs are swapped.
- **Mid Review:** Demo catching a real simulated BOLA attack!

### **Week 3 — Active Defense**
- Tell the eBPF kernel layer to block attacker IPs instantly.
- Add rate limits and bot pattern blockers.

### **Week 4 — Dashboard & Final Polish**
- Mask passwords and personal emails before they hit the screen.
- Polish the React dashboard.
- Final review presentation and project report.

---

## 🧪 How to Run the Tests

The parser module has **zero third-party dependencies**—it runs on pure, fast standard Python!

Run the tests with `pytest`:
```bash
python -m pytest tests/ -v
```

Or run with Python's built-in `unittest`:
```bash
python -m unittest discover -s tests -v
```

Right now, all **17 tests pass in 0.04 seconds**.

---

## 📖 Simple Explanations of Key Terms

* **eBPF:** A cool Linux technology that lets you run small, safe programs inside the operating system kernel. It lets us watch network traffic without installing heavy plugins inside the app.
* **BOLA:** Broken Object Level Authorization. When an API lets User A view User B's private account just by guessing their ID number.
* **BFLA:** Broken Function Level Authorization. When a normal user calls an admin endpoint like `/api/admin/delete_user` and the app forgets to check their role.
* **Shadow API:** An active endpoint running in production that nobody documented in Swagger or OpenAPI.
