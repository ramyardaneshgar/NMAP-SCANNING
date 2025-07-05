# NMAP-SCANNING
Advanced Nmap scanning techniques for reconnaissance, firewall evasion, and TCP/IP behavior analysis using Null, FIN, Xmas, ACK, Window, Fragmented, Spoofed, and Idle scans.

By Ramyar Daneshgar 

## Null Scan (`-sN`)

**Context:** The Null scan sends a TCP packet with all six control flags set to zero. According to the TCP RFC, this configuration is invalid behavior, and many systems drop it silently unless the port is closed.

**Objective:** Determine which ports are closed, and infer which ones are either open or filtered.

**Execution:**

```bash
sudo nmap -sN <target-ip>
```

I ran this scan from the AttackBox after confirming that I had sudo privileges (since raw packet crafting requires elevated permissions). The result showed **7 ports listed as "open|filtered"**, indicating that those ports did not reply with a TCP RST. Since closed ports do return RSTs, I concluded these must be open or being dropped by a firewall silently.

This scan is particularly useful in evading **stateless packet filters**, which primarily detect TCP segments with the SYN flag set. Since the Null scan does not use SYN, such filters fail to recognize it as a connection attempt.

---

## FIN Scan (`-sF`)

**Context:** The FIN scan sends a TCP packet with only the FIN flag enabled. This mimics a graceful connection teardown, even though no session was initiated.

**Objective:** Determine which ports respond with RST, and infer the rest as open|filtered.

**Execution:**

```bash
sudo nmap -sF <target-ip>
```

This returned the same 7 "open|filtered" ports as the Null scan. Since both scans rely on non-standard flag behavior, the results were consistent.

Like the Null scan, FIN scans exploit the **inconsistent handling of unexpected TCP flags** by operating systems. This method can bypass **non-stateful firewalls** and uncover inconsistencies in packet filtering logic.

---

## Xmas Scan (`-sX`)

**Context:** Named for the pattern of lights on a Christmas tree, the Xmas scan sets the FIN, PSH, and URG flags simultaneously—an invalid combination under normal TCP behavior.

**Objective:** Similar to Null and FIN scans, determine open|filtered ports by absence of RSTs.

**Execution:**

```bash
sudo nmap -sX <target-ip>
```

The results again reported **7 ports as open|filtered**. These three scans (Null, FIN, Xmas) are functionally equivalent but vary in how they trigger firewalls or IDS systems.

These scans are ideal for **firewall evasion**, especially against older IDS signatures that detect only SYN-based scans. However, results are ambiguous due to lack of differentiation between "open" and "filtered."

---

## Maimon Scan (`-sM`)

**Context:** This scan sets both FIN and ACK flags. It targets systems that treat unexpected FIN+ACK packets to closed ports with a RST response and silently drop them if open.

**Objective:** Identify BSD-derived systems or hosts with legacy TCP stacks.

**Execution:**

```bash
sudo nmap -sM <target-ip>
```

This scan returned uniform RSTs, indicating that the target system was modern and not vulnerable to this fingerprinting method. Therefore, I could not use this scan to enumerate open ports on the given host.

This scan is valuable in niche scenarios—specifically for **OS fingerprinting** or identifying legacy infrastructure within mixed environments.

---

## ACK Scan (`-sA`)

**Context:** This scan sends a packet with only the ACK flag set. Under normal TCP operations, ACK should only appear in response to previously received data.

**Objective:** Map **firewall rule behavior**, not port state.

**Execution:**

```bash
sudo nmap -sA <target-ip>
```

Initially, I received uniform RSTs, suggesting that all ports were unfiltered (firewall not enabled). However, after a firewall ruleset was applied on the target VM, I re-ran the ACK scan and identified **3 ports returned RSTs**, meaning they were **unfiltered** while others were filtered.

This scan is excellent for **infrastructure reconnaissance**—it distinguishes **stateful firewalls** from packet-filtering ACLs and reveals **which ports bypass perimeter controls**.

---

## Window Scan (`-sW`)

**Context:** An extension of the ACK scan. It analyzes the **TCP window size** of RST responses. Certain systems set a non-zero window only on open ports.

**Objective:** Attempt deeper firewall and OS behavior inference.

**Execution:**

```bash
sudo nmap -sW <target-ip>
```

The output marked the same three ports as **closed**, which contradicted the earlier ACK scan (that marked them as unfiltered). This discrepancy highlighted subtle differences in how the system constructed TCP headers—indicating possibly inconsistent firewall policy enforcement.

The TCP Window scan is primarily used for **indirect port status inference** and **system fingerprinting**. It’s more effective when ACK scans return inconclusive results or when inspecting edge cases.

---

## Custom Flag Scan (`--scanflags`)

**Context:** This allows manual crafting of TCP flags, useful for IDS evasion or protocol behavior testing.

**Execution:**

```bash
sudo nmap --scanflags RSTSYNFIN <target-ip>
```

I chose this combination to test how the system and any intermediate security controls handle malformed packets. The results showed all ports as closed—no surprises, but useful to understand how the system adheres to RFC-compliant flag behavior.

Custom scans are useful in **red teaming** to simulate attacker behavior and validate **IDS/IPS resilience against non-standard protocol manipulation.**

---

## Spoofed Source IP (`-S`)

**Context:** Using a forged source IP address to launch the scan while monitoring from another point on the network.

**Execution:**

```bash
sudo nmap -e eth0 -Pn -S 10.10.10.11 <target-ip>
```

Without a proper sniffing setup, I could not observe the RST replies—highlighting a real-world limitation of spoofing unless you control the spoofed IP or are on a shared broadcast domain.
 
Spoofing is viable only when **response capture is guaranteed**, such as on the same subnet, or with MITM positioning. It's useful for **attribution obfuscation** during advanced assessments.

---

## MAC Spoofing (`--spoof-mac`)

**Context:** Modify the hardware address of the scanning system for anonymity or to bypass MAC-based access control.

**Execution:**

```bash
sudo nmap --spoof-mac 00:11:22:33:44:55 <target-ip>
```

The scan succeeded with no access denial, indicating no MAC-based controls in place.

This technique is relevant in **Wi-Fi security assessments** or against **802.1X MAC filtering** where attackers attempt to impersonate whitelisted devices.

---

## Decoy Scan (`-D`)

**Context:** Insert fake source IPs into the scan to confuse attribution in firewall logs or SIEM tools.

**Execution:**

```bash
sudo nmap -D 192.168.1.10,192.168.1.11,ME <target-ip>
```

Log analysis on the target side showed interleaved scans from decoys and my real IP. This makes correlation more difficult unless full packet capture or correlation with MAC address exists.

Decoys are effective for **log poisoning** and **signature obfuscation**, particularly in **multi-stage intrusion campaigns**.

---

## Fragmentation (`-f`, `--mtu`)

**Context:** Split TCP packets into multiple small fragments to bypass DPI and detection signatures.

**Execution:**

```bash
sudo nmap -sS -p 80 -f <target-ip>
```

Each packet fragment was 8 bytes or less. I confirmed with Wireshark that the system reassembled them, and port 80 returned SYN-ACK successfully.

Packet fragmentation is a **stealth technique** to evade **deep packet inspection**. However, some security appliances reassemble packets before inspection—so this is most effective against older or misconfigured systems.

---

## Idle Scan (`-sI`)

**Context:** A fully stealth scan using a third-party “zombie” host to relay probes and observe IP ID changes.

**Execution:**

```bash
sudo nmap -sI 10.10.5.5 <target-ip>
```

Using a low-traffic printer as the zombie, I recorded the initial IP ID, launched the spoofed probe, then sent another SYN to the zombie to observe IP ID delta. A delta of `2` indicated the target’s port was **open** (because the zombie sent a RST to SYN-ACK).

The Idle Scan is a **zero-interaction reconnaissance** method that leaves **no footprint on the target**, ideal for **clandestine assessments**.

---

## Verbosity and Reasoning (`--reason`, `-v`, `-d`)

**Execution:**

```bash
sudo nmap -sS -F --reason <target-ip>
```

Nmap reported port 22 as open because of a **SYN-ACK** response. Adding `--reason` helped me understand exactly why Nmap classified the state—this is critical for **defensible findings in security audits**.

---

## Lessons Learned

* Each scan type is tuned for **specific evasion objectives**—Null/FIN/Xmas for stealth, ACK/Window for firewall analysis, and Idle for attribution obfuscation.
* Real-world utility depends on **target OS behavior**, **firewall configuration**, and **network positioning**.
* Spoofed and fragmented scans demonstrate how attackers manipulate packet-level behaviors to bypass layered security.
* Decoy and Idle scans show the importance of **network traffic correlation** and **IP ID behavior** in endpoint attribution.

