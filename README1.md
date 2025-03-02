# 🕵️‍♂️ **Bug Bounty Hunting Checklist**  

This checklist provides a **step-by-step** approach to **bug bounty hunting**, covering everything from **reconnaissance to reporting**.  

---

## **🔍 Preparation Phase**  
✅ **Set Up Your Environment**  
- [ ] Use a **dedicated machine or virtual environment** for hunting.  
- [ ] Configure **Burp Suite, OWASP ZAP, Mitmproxy**, or other proxies.  
- [ ] Install **essential tools** (Nmap, Subfinder, FFUF, HTTPX, etc.).  
- [ ] Set up **logging & monitoring** (Burp Collaborator, Interactsh, webhook.site).  
- [ ] Use a **VPN or Tor** if needed for anonymity.  
- [ ] Ensure compliance with **program policies & legal aspects**.  

✅ **Understand the Scope**  
- [ ] Read **bug bounty rules, in-scope/out-of-scope assets, and testing limitations**.  
- [ ] Identify **target technologies** (Wappalyzer, BuiltWith).  
- [ ] Analyze **previous reports & common vulnerabilities** for the program.  

✅ **Set Up Automation**  
- [ ] **Subdomain enumeration** (`subfinder`, `amass`, `assetfinder`, `crt.sh`).  
- [ ] **Port scanning** (`nmap`, `masscan`, `rustscan`).  
- [ ] **Directory fuzzing** (`ffuf`, `dirsearch`, `gobuster`).  
- [ ] **JS/Endpoint enumeration** (`katana`, `linkfinder`, `jsfinder`).  
- [ ] **Wayback & archive analysis** (`gau`, `waybackurls`).  
- [ ] **Live asset checking** (`httpx`, `httprobe`).  
- [ ] **GitHub dorks & secrets scanning** (`GitLeaks`, `trufflehog`).  

---

## **🕵️ Reconnaissance & Vulnerability Hunting**  

### **🔑 Authentication & Session Management**  
- [ ] Test for **default credentials** & **weak passwords**.  
- [ ] **Session hijacking/fixation** (cookies, JWT tokens, OAuth misconfigurations).  
- [ ] **Brute-force login mechanisms** (check rate limiting, captcha bypass).  
- [ ] **Test for improper logout/session expiration issues**.  

### **📌 Injection Attacks**  
- [ ] **SQL Injection (SQLi)** (`' OR '1'='1`, blind SQLi, NoSQLi).  
- [ ] **Cross-Site Scripting (XSS)** (`<script>alert(1)</script>`, DOM-based XSS).  
- [ ] **Server-Side Template Injection (SSTI)** (`{{7*7}}`, `${7*7}`).  
- [ ] **Command Injection** (`; whoami`, `&& cat /etc/passwd`).  

### **🚪 Access Control & IDOR**  
- [ ] Test for **Insecure Direct Object References (IDOR)**.  
- [ ] **Check privilege escalation** by modifying user roles.  
- [ ] **Check API endpoints** for unauthorized data access.  
- [ ] **Try bypassing authentication** (changing cookies, JWT, headers).  

### **📤 File Upload & SSRF**  
- [ ] **Upload unrestricted file types** (`.php`, `.jsp`, `.exe`).  
- [ ] **Check for SSRF (Server-Side Request Forgery)** (`file://`, `http://localhost`).  
- [ ] **Test for LFI/RFI (Local/Remote File Inclusion)** (`../../../etc/passwd`).  

### **🌐 Web & API Security**  
- [ ] **Test API rate limiting & brute force protections**.  
- [ ] **Check for CORS misconfigurations** (`Access-Control-Allow-Origin: *`).  
- [ ] **GraphQL abuse** (`{__schema{types{name}}}`).  
- [ ] **Check for open admin panels (`/admin`, `phpmyadmin`, etc.)**.  

### **☁️ Cloud & Infrastructure Security**  
- [ ] **Scan for exposed S3 buckets, GCP, Azure misconfigurations**.  
- [ ] **Check for open ports & vulnerable services** (Redis, MongoDB, Elasticsearch).  
- [ ] **Test for DNS subdomain takeover** (`nslookup`, `subjack`).  

### **🛡 Blockchain/Web3 Security**  
- [ ] **Analyze smart contracts for vulnerabilities** (Reentrancy, Integer Overflow).  
- [ ] **Check Web3 API security** (RPC abuse, Private Key leaks).  
- [ ] **Inspect DeFi/NFT platforms for exploits**.  

---

## **📝 Reporting & Submitting**  
✅ **Validate the Bug**  
- [ ] **Ensure exploitability & impact**.  
- [ ] **Check for duplicates** on the program’s reports.  
- [ ] **Create a Proof-of-Concept (PoC)** (screenshots, code snippets, or video).  

✅ **Write a Clear Report**  
- **Title:** Short and descriptive.  
- **Summary:** Explain the impact in simple terms.  
- **Steps to Reproduce:** Clear and detailed instructions.  
- **PoC (Proof of Concept):** Screenshots, requests, or videos.  
- **Impact Explanation:** Why this is a security risk.  
- **Suggested Fix:** Recommendations for mitigation.  

✅ **Submit & Track**  
- [ ] **Submit on Bugcrowd, HackerOne, or other platforms**.  
- [ ] **Monitor response from the triage team**.  
- [ ] **Improve and hunt for more!** 🚀  

---

## **📚 Continuous Learning & Improvement**  
✅ **Follow Security Blogs & CVE Disclosures**  
✅ **Refine Recon & Exploitation Tools**  
✅ **Improve Report-Writing & Communication**  
✅ **Participate in CTFs & Security Challenges**  
✅ **Engage with the Bug Bounty Community**  

---

This checklist keeps you **organized & efficient** in bug bounty hunting! Do you need it **customized** for a specific **program or target**? 🚀