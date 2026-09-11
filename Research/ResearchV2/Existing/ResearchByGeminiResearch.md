# **Enterprise Cryptographic Discovery and Post-Quantum Posture Analysis: Architecture, Market Capabilities, and Inherent Engineering Deficits**

The convergence of quantum computing hardware maturation and cryptanalytic theory poses an existential threat to classical asymmetric cryptography1. Fault-tolerant quantum architectures executing Shor’s algorithm will render prevalent public-key cryptosystems—specifically those relying on integer factorization and discrete logarithms over finite fields and elliptic curves—computationally tractable2. In response, global regulatory authorities, defense agencies, and enterprise security frameworks have mandated transitioning to Post-Quantum Cryptography (PQC) standards, notably the lattice-based Federal Information Processing Standards (FIPS 203, 204, and 205\)6.

Implementing PQC within distributed enterprise estates requires comprehensive visibility into existing cryptographic footprints2. The Enterprise Cryptographic Discovery and Analysis Tool (ECDAT) discipline has emerged to resolve this visibility challenge2. Operating beyond the boundary of traditional Software Bills of Materials (SBOMs), an ECDAT must catalog cryptographic primitives across static code, compiled binaries, dynamic process memory, network fabrics, and cloud environments, serializing these findings into standardized Cryptography Bills of Materials (CBOMs)9.

Despite rapid commercialization and adoption among early adopters, prevailing market-leading platforms exhibit severe architectural limitations5. Many existing solutions act merely as diagnostic inventories, introducing excessive operational overhead, high false positive ratios, static-dynamic data fragmentation, and unexecutable recommendations5. A detailed examination of market-leading system designs reveals significant technical deficits and demonstrates why current enterprise deployments often struggle to achieve operational agility4.

## **Market-Leading Architectures and Solution Paradigms**

The enterprise cryptographic discovery and management market is dominated by several foundational platforms, each approaching asset identification from a distinct architectural vantage point6.

&nbsp;

| Platform | Core Discovery Modalities | Underlying Engine Architecture | CBOM Standardization | Primary Deployment Targets |
| :---- | :---- | :---- | :---- | :---- |
| **IBM Quantum Safe Explorer** | Static Source Code Scanning, Compiled Binary Analysis, Build Artifact Inspection1. | Inter-procedural Abstract Syntax Tree (AST) parsing, control-flow graph (CFG) taint tracking via the Hyperion engine; CLI and IDE extensions2. | CycloneDX 1.6 / 1.7 JSON, proprietary CBOM JSON schema10. | Polyglot enterprise codebases, continuous integration pipelines, mainframe/Z-Linux environments1. |
| **SandboxAQ AQtive Guard** | Dynamic Process Tracing, Passive Network Telemetry, Host Filesystem Scans12. | Java Virtual Machine (JVM) bytecode rewriting, dynamic linker LD\_PRELOAD hooks (libssl/libcrypto), and network tap analyzers; GraphQL API core13. | Ingests and exports CycloneDX CBOM, normalized graph database models13. | Dynamic microservices, runtime container workloads, enterprise network edges12. |
| **Keyfactor Command (InfoSec Global AgileSec)** | Host-Based OS Sensors, Network Handshake Dissection, PKI/Certificate Enumeration12. | Host agents (integrated natively or via Tanium/CrowdStrike), active/passive network protocol probes, and cryptographic store scrapers12. | Proprietary inventory schema mapped to CycloneDX 1.6 and JSON/CSV outputs9. | Hybrid cloud infrastructure, enterprise trust stores, Hardware Security Modules (HSMs), network appliances6. |
| **Encryption Consulting CBOM Secure** | Multi-Cloud KMS Connectors, Agentless Host Scanning, Secrets Vault Scrapers, Static Source Plugins6. | Cloud provider API ingestion daemons, software supply chain scanners, and automated certificate lifecyclers6. | Native CycloneDX 1.6 / ECMA-424 JSON and XML schemas6. | Multi-cloud infrastructures, centralized Key Management Services, enterprise secrets vaults6. |

### **Static Inspection and Syntax-Tree Decomposition**

IBM Quantum Safe Explorer relies primarily on deep static application security testing (SAST) principles adapted specifically for cryptographic identification2. The platform ingests application source trees across diverse programming languages, including Java, C, C++, C\#, Python, Go, and TypeScript14. At its core, the analysis engine translates raw code into unified intermediate representations and Abstract Syntax Trees2. Rather than depending on simple regular-expression matching, the system traces data flow across procedural boundaries2.

This inter-procedural taint analysis allows the scanner to identify the invocation of cryptographic factory APIs, such as Java’s Cipher.getInstance() or OpenSSL’s EVP\_get\_cipherbyname(), and trace the assignment of algorithm configuration strings throughout variable assignments, constant pool lookups, and wrapper classes2. The primary output is a detailed dependency graph distinguishing between components that merely bundle cryptographic libraries and those that actively execute them10.

### **Dynamic Process Interception and Network Observation**

SandboxAQ took a different architectural path by acquiring Cryptosense and building AQtive Guard, prioritizing runtime observation over static source scanning12. Recognizing that static analysis often misses dynamically configured ciphers, AQtive Guard monitors running processes from within user space12.

For Java environments, the architecture deploys a runtime agent using the \-javaagent JVM parameter, dynamically injecting bytecode instrumentation at class-load time to intercept calls to the Java Cryptography Architecture (JCA) and Java Cryptography Extension (JCE) providers13.

In Linux environments executing compiled native C and C++ binaries, AQtive Guard relies on dynamic linker interception via the LD\_PRELOAD environment variable19. Interceptor shared objects, such as libssl\_tracer.so and evp\_tracer.so, sit between the host application and core system libraries like OpenSSL19. When an application initiates a handshake or wraps an envelope, the tracer intercepts the API call, records parameter sets, key lengths, and operational modes, and then forwards the call to the underlying cryptographic shared object13.

This user-space tracing is augmented by passive network sniffing engines that capture external and internal TLS handshakes without decrypting operational payloads, verifying protocol negotiation, certificate validity, and cipher suite parameters in transit6.

### **Host-Centric and Control-Plane Inventorying**

Keyfactor’s integration of InfoSec Global’s AgileSec Analytics focuses on host operating systems, cryptographic storage repositories, and network communication channels12. This approach scans operating system credential stores, Java KeyStores (JKS), PKCS\#12 bundles, and centralized Hardware Security Modules6. Rather than parsing source code logic, host-centric tools extract compiled binaries and system libraries, examining their dynamic link headers and symbol tables to determine if deprecated cryptographic providers are accessible within system paths4.

To operate at scale without generating excessive endpoint footprint, these platforms often integrate with existing endpoint detection and response (EDR) fabrics, such as Tanium or CrowdStrike, to query filesystems asynchronously12. This capability is paired with control-plane connectors that query cloud infrastructure management planes—including AWS Key Management Service, Azure Key Vault, Google Cloud KMS, and HashiCorp Vault—to catalog managed keys, rotation parameters, and signing certificates directly from cloud provider metadata6.

## **Standardization and Representation: The CycloneDX CBOM Model**

A core deliverable for any discovery platform is the Cryptography Bill of Materials, an extension of the software supply chain standard designed to provide a machine-readable, auditable inventory of cryptographic dependencies9. The industry has largely converged on the OWASP CycloneDX 1.6 and 1.7 specifications, formalized under ECMA-42410.

Within the CycloneDX schema, cryptographic entities are defined as first-class components under the type cryptographic-asset10. The schema specifies the exact metadata required to evaluate an asset's vulnerability to quantum computing:

&nbsp;

&nbsp;

&nbsp;

JSON

{  
  "bomFormat": "CycloneDX",  
  "specVersion": "1.6",  
  "serialNumber": "urn:uuid:65a0b947-8bfa-4c22-9214-88efb88cb7d1",  
  "version": 1,  
  "metadata": {  
    "timestamp": "2026-03-30T10:15:00Z",  
    "component": {  
      "type": "application",  
      "bom-ref": "app-payment-gateway@4.2.0",  
      "name": "Payment Gateway Service",  
      "version": "4.2.0"  
    }  
  },  
  "components": \[  
    {  
      "type": "cryptographic-asset",  
      "bom-ref": "crypto-alg-rsa-2048",  
      "name": "RSA",  
      "cryptoProperties": {  
        "assetType": "algorithm",  
        "primitive": "signature",  
        "parameterSetIdentifier": "2048",  
        "classicalSecurityLevel": 112,  
        "nistQuantumSecurityLevel": 0,  
        "cryptoFunctions": \["sign", "verify"\]  
      }  
    },  
    {  
      "type": "cryptographic-asset",  
      "bom-ref": "crypto-cert-tls-leaf",  
      "name": "api.enterprise.internal",  
      "cryptoProperties": {  
        "assetType": "certificate",  
        "certificateProperties": {  
          "subjectName": "CN=api.enterprise.internal",  
          "issuerName": "CN=Enterprise Internal Intermediate CA",  
          "notValidAfter": "2027-05-01T00:00:00Z",  
          "signatureAlgorithmRef": "crypto-alg-rsa-2048",  
          "subjectPublicKeyRef": "crypto-key-rsa-2048"  
        }  
      }  
    }  
  \],  
  "dependencies": \[  
    {  
      "ref": "app-payment-gateway@4.2.0",  
      "dependsOn": \["crypto-alg-rsa-2048", "crypto-cert-tls-leaf"\]  
    }  
  \]  
}

The schema distinguishes between two fundamental dependency structures via its relationship modeling: implements dependencies, which indicate that a software library or module contains the executable logic for a cryptographic algorithm, and uses dependencies, which demonstrate that an application actively executes the algorithm during normal runtime flows10.

This distinction prevents inventory engines from confusing latent library code with active cryptographic executions, enabling risk engines to prioritize assets based on verified runtime use10.

## **Quantum Risk Frameworks and Mosca’s Theorem**

Transforming raw CBOM outputs into an actionable risk assessment requires evaluating assets against post-quantum risk models9. Threat evaluation centers around the "Harvest Now, Decrypt Later" (HNDL) attack vector, where adversaries passively intercept and store encrypted enterprise traffic and sensitive files1. Although classical adversaries cannot decrypt these streams today, they can process the archived ciphertext retroactively once a CRQC capable of running Shor's algorithm is deployed1.

### **Formalization of Mosca’s Inequality**

Evaluating organizational vulnerability to HNDL attacks relies on Mosca’s Theorem3. The framework establishes a mathematical model balancing three temporal variables:

* **Migration Latency (![][image1])**: The operational time required to re-architect systems, validate compliance, deploy post-quantum algorithms, and decommission legacy infrastructure across the entire organization8.  
* **Data Confidentiality Lifetime (![][image2])**: The required duration over which the information must remain strictly confidential, defined by regulatory standards (e.g., healthcare records, financial ledgers, state secrets) or proprietary requirements8.  
* **Quantum Horizon (![][image3])**: The estimated duration until an adversary operates a Cryptographically Relevant Quantum Computer capable of breaking standard asymmetric primitives8.

The vulnerability condition is formalized as an inequality:

![][image4]

![][image5]

When ![][image6], an organization can complete migration before the quantum threshold arrives, ensuring data generated post-migration remains protected8. However, when ![][image7], an active security deficit exists8. Data encrypted under legacy public-key algorithms during this exposure window is vulnerable to passive interception and subsequent post-quantum compromise8.

To illustrate how these variables interact over time, consider an enterprise evaluating risk from the current deployment date. The timeline begins today, with migration operations taking ![][image1] years to complete. Concurrently, the data produced requires ![][image2] years of confidentiality protection. If the combined span of migration and retention (![][image8]) extends past the estimated arrival of a CRQC (![][image3] years from today), the system enters an active security deficit. The duration by which ![][image8] overshoots ![][image3] represents the window where encrypted records are exposed to Harvest Now, Decrypt Later attacks8.

&nbsp;

| Domain / Industry Sector | Typical Migration Latency (X) | Typical Data Lifetime (Y) | Industry Consensus Horizon (Z) | Security Margin Status (Δ=X+Y−Z) | Immediate Operational Imperative |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **Defense & National Security** | 10–15 years29 | 50–75 years29 | 7–10 years8 | Deficit (![][image9])29 | Mandated immediate PQC migration under CNSA 2.0 timelines8. |
| **Healthcare & Genomics** | 7–12 years29 | 50+ years (Patient Lifespan)29 | 7–10 years8 | Deficit (![][image9])29 | Immediate deployment of hybrid key exchange for all patient records8. |
| **Financial Services** | 5–10 years29 | 7–25 years29 | 7–10 years8 | Deficit (![][image10])29 | Prioritize core banking infrastructure and cross-border settlement channels29. |
| **Enterprise Software / SaaS** | 3–7 years29 | 5–10 years29 | 7–10 years8 | Critical / Borderline (![][image11])29 | Establish continuous automated CBOM generation and CI/CD policy gates9. |
| **Retail & Ephemeral Commerce** | 2–4 years29 | 1–3 years29 | 7–10 years8 | Compliant / Safe (![][image12])29 | Monitor upstream library dependencies; update on standard hardware lifecycles8. |

### **Algorithmic Replacement and Tradeoff Dynamics**

When an ECDAT platform flags a vulnerable cryptographic primitive, its recommendation engine must select a replacement that meets security requirements without degrading system performance7.

The primary post-quantum primitives standardized by NIST introduce distinct performance characteristics compared to classical algorithms7.

&nbsp;

| Algorithm Primitive | Standardized Specification | Primitive Class | Public Key Overhead | Ciphertext / Signature Overhead | Processing Profile | Primary Performance Bottlenecks |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| **RSA-2048** (Classical) | PKCS\#1 v2.2 | Asymmetric Signature / Encryption | 256 bytes7 | 256 bytes7 | Asymmetric; fast verification, compute-intensive signing7. | Completely broken by Shor's algorithm; deprecated by NIST4. |
| **X25519** (Classical) | RFC 7748 | Elliptic-Curve Diffie-Hellman | 32 bytes7 | 32 bytes7 | Highly optimized constant-time scalar multiplication7. | Completely broken by Shor's algorithm; zero quantum security2. |
| **ML-KEM-768** (Post-Quantum) | FIPS 203 (Kyber) | Module Lattice Key Encapsulation | 1,184 bytes7 | 1,088 bytes7 | Fast polynomial vector multiplication; minimal CPU cycles7. | Key and ciphertext expansion exceeds single-packet boundaries in constrained networks30. |
| **ML-KEM-1024** (Post-Quantum) | FIPS 203 (Kyber) | Module Lattice Key Encapsulation | 1,568 bytes7 | 1,568 bytes7 | High security margin; requires matrix NTT operations7. | Public keys exceed typical 1,500-byte MTU envelopes, forcing IP-level fragmentation7. |
| **ML-DSA-65** (Post-Quantum) | FIPS 204 (Dilithium) | Module Lattice Digital Signature | 1,952 bytes7 | 3,309 bytes7 | Balanced signing and verification speed; reject sampling required7. | Signature size (3.3 KB) inflates TLS handshake chains, triggering TCP segmentation7. |
| **SLH-DSA-128s** (Post-Quantum) | FIPS 205 (SPHINCS+) | Stateless Hash-Based Digital Signature | 32 bytes | 7,856 bytes | Highly compute-intensive; thousands of SHA-256 / SHAKE evaluations. | Signature size (7.8 KB) severely degrades network throughput; slow signing latency. |

To manage this transition securely, the industry relies on hybrid key exchange protocols, such as pairing X25519 with ML-KEM-7688. This approach maintains compliance with existing FIPS requirements while protecting against quantum attacks through the post-quantum lattice component8.

However, as shown in the table above, post-quantum cryptography introduces significant data expansion7. While classical keys fit within tens or hundreds of bytes, lattice-based public keys and signatures require thousands of bytes7. This expansion introduces network and transport-layer challenges that recommendation engines must actively account for30.

## **Architectural Deficiencies and Ignored Enterprise Feedback**

Despite marketing claims of seamless post-quantum readiness, real-world enterprise deployments frequently reveal major architectural weaknesses in current market-leading tools5. These issues stem from fundamental engineering tradeoffs in how discovery engines are constructed and maintained5.

### **The Remediation Actionability Gap**

The most pervasive user criticism of modern cryptographic discovery tools is that they produce massive inventories without actionable remediation paths—a challenge often referred to in enterprise environments as the "expensive spreadsheet problem"9.

Current platforms operate almost entirely as diagnostic scanners9. They scan code repositories and cloud estates to generate extensive lists of quantum-vulnerable ciphers, but fail to provide automated mechanisms to remediate the underlying code9.

Remediation engines rarely generate contextual, automated pull requests or refactor Abstract Syntax Trees to replace deprecated APIs with crypto-agile wrapper interfaces9. Security teams are left with raw inventories identifying thousands of vulnerabilities across hundreds of microservices, without the tools or guidance needed to coordinate remediation across distributed engineering groups5. As a result, the discovered CBOM quickly drifts out of sync with production codebases5.

### **Static and Dynamic Reconciliation Failures**

A major architectural flaw in current discovery platforms is the failure to reconcile static source-code analysis with dynamic runtime monitoring12.

Static code scanners trace Abstract Syntax Trees within source repositories, but cannot determine whether a given code path is ever invoked in production12. In modern enterprise architectures, cryptographic parameters are frequently loaded at runtime from environment variables, database records, remote secrets managers, or configuration files12. Static analyzers flag the potential presence of an algorithm without verifying its active execution status10.

Conversely, dynamic agents capture only executed code paths, leaving dormant disaster-recovery routines, annual financial closing jobs, and fallback communication channels completely uninspected13.

Because market leaders rarely unify static source graphs with dynamic execution traces, organizations are caught between two incomplete datasets13. Static scans report high volumes of unvalidated findings, while dynamic monitors miss unexercised code paths13. The resulting divergence requires manual cross-referencing, significantly inflating verification overhead5.

### **Computational Scalability and CI/CD Overhead**

Enterprise development environments require security tools to execute rapidly within automated CI/CD pipelines1. However, static cryptographic discovery engines often experience performance bottlenecks when analyzing large, polyglot repositories14.

Constructing full inter-procedural call graphs and taint-tracking Abstract Syntax Trees across large Java, C++, or Python monoliths consumes significant compute resources12. Scanners often require 32 GB to 64 GB of local memory and can encounter out-of-memory heap exhaustion when scanning large enterprise codebases14.

When developers experience build pipeline timeouts, they frequently resort to adding broad directory exclusions to their scanning configurations15. This practice circumvents the scanner's depth and leaves critical application paths uninspected15.

### **Contextual Blindness and Risk Inflation**

Current discovery engines inspect code syntax without accounting for the surrounding operational context5.

A scanner will typically flag a deprecated cryptographic primitive—such as MD5, SHA-1, or RSA-1024—with the same high-severity rating, regardless of whether it is used in a production payment authentication workflow, an internal logging hash, a test harness, or a checksum verification step15.

Because discovery tools do not integrate with enterprise data governance catalogs, they cannot infer the confidentiality requirements or lifetime (![][image2]) of the underlying data5.

Applying a uniform high-severity rating to ephemeral cache hashes and long-term customer records alike produces severe alert fatigue5. Security teams spend valuable time filtering through false positives instead of addressing critical quantum vulnerabilities protecting sensitive business data5.

### **Transport-Layer Failures in Algorithmic Recommendations**

Automated recommendation engines frequently suggest post-quantum replacements based solely on cryptographic security parameters, without evaluating physical network infrastructure constraints7.

When an engine recommends upgrading a TLS architecture from classical elliptic-curve keys to ML-KEM-1024 or an ML-DSA-65 signature scheme, it often overlooks the network implications of larger key sizes7. The public keys and signatures of these algorithms significantly exceed standard Ethernet Maximum Transmission Units (MTUs) of 1,500 bytes7.

When an application initiates a handshake using these larger post-quantum primitives, the transport layer must segment the public key across multiple IP frames30.

Across real-world enterprise infrastructure, this packet fragmentation introduces significant reliability issues30:

* **Middlebox Packet Drops**: Enterprise firewalls, server load balancers, and Intrusion Detection Systems (IDS) frequently drop out-of-order IP fragments or packets that exceed strict buffer sizes, mistaking them for fragmentation-based denial-of-service attacks30.  
* **Asymmetric Routing Failures**: In multi-homed cloud networks, fragmented handshake packets may traverse different network paths, causing packet reassembly failures at edge ingress controllers.  
* **Handshake Timeouts and Retransmissions**: The need to transmit multiple network frames per handshake increases latency and the probability of packet loss, causing client connection timeouts and session resets30.

Because existing recommendation engines do not evaluate network topologies, path MTUs, or middlebox configurations, organizations that implement these recommendations risk unexpected outages across their production networks30.

### **Operational Friction and Deployment Resistance**

Vendor platforms that depend on invasive dynamic agents (LD\_PRELOAD hooks, native kernel modules, or bytecode instrumentation) face significant resistance from infrastructure and site reliability engineering teams4.

Injecting dynamic interception libraries into latency-sensitive microservices introduces memory overhead and operational risk12. In production environments, any stability issue within a monitoring agent can trigger cascading failures across the host application4.

Dynamic tracers also create security risks34. When an agent intercepts function calls to OpenSSL or Java cryptographic providers to inspect cipher parameters, it risks exposing sensitive material—such as initialization vectors, intermediate hashing buffers, or plaintext keys—into debug logs or cloud collector endpoints, creating compliance violations34.

Furthermore, in operational technology (OT), industrial control networks, and embedded platforms (e.g., aerospace and defense systems certified under DO-178C or IEC 62443), third-party monitoring agents are explicitly prohibited4. As a result, these specialized environments remain blind spots for dynamic discovery platforms4.

## **Architectural Comparison: Commercial Implementations vs. Enterprise Requirements**

Evaluating market-leading discovery platforms against enterprise migration needs reveals significant gaps in how these tools handle discovery, risk modeling, and remediation execution4.

&nbsp;

| Architectural Domain | Current Commercial Implementation | Operational Impact | Enterprise Requirements for Next-Generation ECDAT |
| :---- | :---- | :---- | :---- |
| **Discovery Scope & Integration** | Distinct tools operate in silos: static code analyzers do not track runtime states, while dynamic tracers only observe active code paths12. | Incomplete coverage; static scans leave dynamic configurations unresolved, while dynamic tools miss dormant failover logic5. | Unified engines that combine static Abstract Syntax Trees with non-invasive dynamic runtime telemetry (such as eBPF) into a reconciled cryptographic call graph13. |
| **Data Lifetime Modeling (![][image2])** | Algorithms are evaluated in isolation based on mathematical strength, ignoring the operational lifetime of the underlying data5. | Flawed risk prioritization; ephemeral hashes receive the same severity ratings as long-term sensitive customer records8. | Integration with enterprise data governance catalogs to dynamically pull data retention schedules into Mosca's inequality calculations8. |
| **Scanning Scalability** | Heavy static analysis engines suffer from memory bloat and JVM out-of-memory errors on large monoliths14. | Engineering teams bypass scans or exclude subdirectories to prevent CI/CD pipeline timeouts15. | Language-agnostic, incremental static analysis with caching and parallelized container layer inspection6. |
| **Network & Transport Awareness** | Recommendations propose post-quantum algorithms without evaluating network path constraints or packet size limitations7. | Systems experience dropped handshakes, packet fragmentation at firewalls, and connection resets30. | Network-aware recommendation engines that evaluate path MTUs, protocol configurations, and load balancer compatibility before suggesting PQC primitives30. |
| **Remediation Execution** | Tools provide static dashboards and raw CBOM exports without actionable remediation mechanisms9. | Discovery efforts stall after generating inventories; development teams lack automated paths to execute migrations5. | Automated code refactoring, Abstract Syntax Tree pull-request generation, and dynamic crypto-agile proxy routing9. |
| **Edge, OT, and Embedded Support** | Systems require invasive dynamic agents (LD\_PRELOAD, JVM byte-code hooks) or direct access to source code4. | Legacy systems, mainframes, and safety-critical operational technologies remain uninspected blind spots4. | Passive network sniffing, simulated TLS handshake probing, and non-invasive firmware binary analysis2. |

## **Technical Synthesis and Strategic Architectural Roadmap**

The transition to post-quantum cryptography represents a fundamental architectural modernization across enterprise software and infrastructure5. Current market-leading cryptographic discovery tools have made significant progress by standardizing machine-readable inventories using the CycloneDX 1.6 and 1.7 CBOM formats10.

However, existing platforms remain limited by their diagnostic focus9. Relying on isolated static scans or invasive dynamic agents leads to incomplete coverage, high false-positive rates, and unexecutable recommendations5.

To address these challenges, next-generation Enterprise Cryptographic Discovery and Analysis Tools must integrate discovery, analysis, and remediation into a cohesive workflow5:

* **Unified Multi-Tier Discovery**: Platforms must reconcile static code analysis with non-invasive runtime observation13. Using eBPF probes in Linux kernel space allows tools to monitor active cryptographic operations and cipher negotiations without the performance and stability risks of LD\_PRELOAD or JVM bytecode modification39. Merging dynamic observations with static Abstract Syntax Trees produces a comprehensive, verified cryptographic call graph10.  
* **Context-Aware Quantum Risk Modeling**: Risk engines must move beyond analyzing algorithms in isolation5. By integrating with enterprise data catalogs and compliance repositories, discovery tools can accurately determine the confidentiality lifetime (![][image2]) of underlying data assets8. Applying Mosca’s inequality (![][image13]) with verified operational parameters ensures that migration priorities align with genuine business risks, mitigating alert fatigue8.  
* **Transport-Aware Recommendation Engines**: Migration recommendations must account for physical network constraints7. Rather than recommending post-quantum primitives based solely on theoretical security margins, tools must evaluate key sizes, path MTUs, and transport protocols30. Where direct adoption of large-footprint algorithms like ML-DSA would cause packet fragmentation and dropped handshakes, engines should recommend balanced hybrid schemes (e.g., X25519 \+ ML-KEM-768) or stateful hash-based alternatives optimized for the target environment8.  
* **Automated Remediation Execution**: Discovery platforms must bridge the gap between reporting vulnerabilities and executing fixes9. Integrating with developer workflows via automated pull requests, AST-based code transformations, and crypto-agile proxy routing allows organizations to translate CBOM inventories directly into coordinated engineering tasks9.

Adopting an integrated, context-aware approach enables organizations to move beyond static spreadsheets and build an agile, defensible cryptographic posture capable of withstanding emerging quantum threats5.

#### **Works cited**

> 1. IBM Quantum Safe Explorer \- ResearchGate, [https://www.researchgate.net/profile/Ahmed-Al-Qatatsheh-2/post/How\_do\_I\_measure\_the\_energy\_consumption\_of\_an\_Algorithm\_on\_a\_scientific\_and\_cost-efficient\_way/attachment/656102983e8c356740da6da0/AS%3A11431281206737492%401700856472225/download/IBM+Quantum+Safe+Explorer.pdf](https://www.researchgate.net/profile/Ahmed-Al-Qatatsheh-2/post/How_do_I_measure_the_energy_consumption_of_an_Algorithm_on_a_scientific_and_cost-efficient_way/attachment/656102983e8c356740da6da0/AS%3A11431281206737492%401700856472225/download/IBM+Quantum+Safe+Explorer.pdf)  
> 2. draft-liu-cadi-01 \- Cryptographic Asset Discovery and Inventory, [https://datatracker.ietf.org/doc/draft-liu-cadi/](https://datatracker.ietf.org/doc/draft-liu-cadi/)  
> 3. Implementation of Quantum Safe Ecosystem in India, [https://dst.gov.in/sites/default/files/Report\_TaskForce\_PQMigration\_4Feb26%20%28v1%29.pdf](https://dst.gov.in/sites/default/files/Report_TaskForce_PQMigration_4Feb26%20%28v1%29.pdf)  
> 4. Cryptographic Asset Discovery and Inventory for Embedded Systems, [https://www.preprints.org/manuscript/202601.1422](https://www.preprints.org/manuscript/202601.1422)  
> 5. Post-Quantum Discovery as a Governance Capability \- arXiv, [https://arxiv.org/pdf/2605.16549](https://arxiv.org/pdf/2605.16549)  
> 6. Top Cryptographic Inventory Vendors and Methodologies, [https://www.encryptionconsulting.com/cryptographic-inventory-vendors/](https://www.encryptionconsulting.com/cryptographic-inventory-vendors/)  
> 7. Design and implementation of an authenticated post-quantum, [https://www.frontiersin.org/journals/physics/articles/10.3389/fphy.2025.1723966/full](https://www.frontiersin.org/journals/physics/articles/10.3389/fphy.2025.1723966/full)  
> 8. Data Lifetime Encryption Decision Framework: Mosca Inequality, [https://quantumsecuritydefence.com/insights/data-lifetime-encryption-decision-frame/](https://quantumsecuritydefence.com/insights/data-lifetime-encryption-decision-frame/)  
> 9. What Is a CBOM? Cryptographic Bill of Materials Explained, [https://www.qnulabs.com/blog/the-cryptographic-bill-of-materials-cbom-what-it-is-why-regulators-now-require-it-and-what-comes-after-discovery](https://www.qnulabs.com/blog/the-cryptographic-bill-of-materials-cbom-what-it-is-why-regulators-now-require-it-and-what-comes-after-discovery)  
> 10. IBM/CBOM: Cryptography Bill of Materials \- GitHub, [https://github.com/IBM/CBOM](https://github.com/IBM/CBOM)  
> 11. What Is a CBOM? Cryptography Bill of Materials, [https://www.encryptionconsulting.com/education-center/what-is-a-cbom/](https://www.encryptionconsulting.com/education-center/what-is-a-cbom/)  
> 12. Cryptographic Inventory Vendors and Methodologies, [https://postquantum.com/post-quantum/cryptographic-inventory-vendors/](https://postquantum.com/post-quantum/cryptographic-inventory-vendors/)  
> 13. Call site fundamentals \- AQtive Guard \- SandboxAQ, [https://aqtiveguard.sandboxaq.com/docs/fundamentals/callsite-fundamentals/](https://aqtiveguard.sandboxaq.com/docs/fundamentals/callsite-fundamentals/)  
> 14. IBM Quantum Safe Explorer overview, [https://www.ibm.com/docs/en/quantum-safe/quantum-safe-explorer/2.x?topic=quantum-safe-explorer-overview](https://www.ibm.com/docs/en/quantum-safe/quantum-safe-explorer/2.x?topic=quantum-safe-explorer-overview)  
> 15. IBM Quantum Safe Explorer steps for Python code scanning, [https://www.ibm.com/docs/en/quantum-safe/quantum-safe-explorer/2.x?topic=scanning-steps-python-code](https://www.ibm.com/docs/en/quantum-safe/quantum-safe-explorer/2.x?topic=scanning-steps-python-code)  
> 16. Sandboxaq | APIs.io Providers, [https://apis.io/providers/sandboxaq/](https://apis.io/providers/sandboxaq/)  
> 17. Filesystem Scanner reference \- AQtive Guard, [https://aqtiveguard.sandboxaq.com/docs/sensors/filesystem-scanner/reference/](https://aqtiveguard.sandboxaq.com/docs/sensors/filesystem-scanner/reference/)  
> 18. Java Tracer reference \- AQtive Guard, [https://aqtiveguard.sandboxaq.com/docs/sensors/java-tracer/reference/](https://aqtiveguard.sandboxaq.com/docs/sensors/java-tracer/reference/)  
> 19. OpenSSL Tracer getting started guide \- AQtive Guard, [https://aqtiveguard.sandboxaq.com/docs/sensors/openssl-tracer/getting-started/](https://aqtiveguard.sandboxaq.com/docs/sensors/openssl-tracer/getting-started/)  
> 20. Getting started \- AQtive Guard User Guide, [https://docs.aqtiveguard.com/getting-started/](https://docs.aqtiveguard.com/getting-started/)  
> 21. Global PQC Migration Platform Market Share and Ranking, Overall, [https://qyresearch.in/report-details/8365917](https://qyresearch.in/report-details/8365917)  
> 22. Migration to Post-Quantum Cryptography Quantum Readiness, [https://outlook.stpi.niar.org.tw/pdfview/tdop/4b1141008d55b2f3018dbee4541436bf](https://outlook.stpi.niar.org.tw/pdfview/tdop/4b1141008d55b2f3018dbee4541436bf)  
> 23. Cryptography Bill of Materials (CBOM) | Mondoo Docs, [https://mondoo.com/docs/xgrep/code-scanning/cbom](https://mondoo.com/docs/xgrep/code-scanning/cbom)  
> 24. Maven Plugin reference \- AQtive Guard, [https://aqtiveguard.sandboxaq.com/docs/integrations/maven-plugin/reference/](https://aqtiveguard.sandboxaq.com/docs/integrations/maven-plugin/reference/)  
> 25. Inventory Management Use Case: Cryptographic Certificate, [https://cyclonedx.org/use-cases/cryptographic-certificate/](https://cyclonedx.org/use-cases/cryptographic-certificate/)  
> 26. Inventory Management Use Case: Cryptographic Algorithm, [https://cyclonedx.org/use-cases/cryptographic-algorithm/](https://cyclonedx.org/use-cases/cryptographic-algorithm/)  
> 27. PQC Migration and CBOM Tools Comparison: 2026 Buyer's Guide, [https://www.qcecuring.com/blog/pqc-migration-tools-comparison](https://www.qcecuring.com/blog/pqc-migration-tools-comparison)  
> 28. Architecture-Derived CBOMs for Cryptographic Migration \- arXiv, [https://arxiv.org/html/2603.22442v1](https://arxiv.org/html/2603.22442v1)  
> 29. Quantum Computing Timeline and Threat Assessment \- QCecuring, [https://www.qcecuring.com/blog/quantum-computing-timeline-threat-assessment](https://www.qcecuring.com/blog/quantum-computing-timeline-threat-assessment)  
> 30. Evaluating Post-Quantum Cryptography in IoT Networks \- MDPI, [https://www.mdpi.com/1999-5903/18/6/316](https://www.mdpi.com/1999-5903/18/6/316)  
> 31. Medium \- Level Up Coding \- GitConnected, [https://levelup.gitconnected.com/your-encryption-has-an-expiration-date-nist-just-published-the-replacement-8f20ca31f61a](https://levelup.gitconnected.com/your-encryption-has-an-expiration-date-nist-just-published-the-replacement-8f20ca31f61a)  
> 32. (PDF) Design and implementation of an authenticated post-quantum, [https://www.researchgate.net/publication/399579709\_Design\_and\_implementation\_of\_an\_authenticated\_post-quantum\_session\_protocol\_using\_ML-KEM\_Kyber\_ML-DSA\_Dilithium\_and\_AES-256-GCM](https://www.researchgate.net/publication/399579709_Design_and_implementation_of_an_authenticated_post-quantum_session_protocol_using_ML-KEM_Kyber_ML-DSA_Dilithium_and_AES-256-GCM)  
> 33. Post-Quantum TLS in 2026: Surviving Packet Fragmentation and, [https://sigdelsushil.com.np/blog/post-quantum-tls-in-2026-surviving-packet-fragmentation-and-handshake-blowup-in-distributed-systems.html](https://sigdelsushil.com.np/blog/post-quantum-tls-in-2026-surviving-packet-fragmentation-and-handshake-blowup-in-distributed-systems.html)  
> 34. From Algebraic Correctness to Zero Trust Deployment \- MDPI, [https://www.mdpi.com/2079-9292/15/15/3427](https://www.mdpi.com/2079-9292/15/15/3427)  
> 35. Cryptoscope: Analyzing cryptographic usages in modern software, [https://www.alphaxiv.org/abs/2503.19531](https://www.alphaxiv.org/abs/2503.19531)  
> 36. Static Discovery and Assessment of Cryptographic Assets in Software, [https://www.researchgate.net/publication/411715202\_Hidden\_Ciphers\_and\_Where\_to\_Find\_Them\_Static\_Discovery\_and\_Assessment\_of\_Cryptographic\_Assets\_in\_Software](https://www.researchgate.net/publication/411715202_Hidden_Ciphers_and_Where_to_Find_Them_Static_Discovery_and_Assessment_of_Cryptographic_Assets_in_Software)  
> 37. Post-Quantum Cryptography Key Management | CSA, [https://cloudsecurityalliance.org/artifacts/post-quantum-cryptography-key-management](https://cloudsecurityalliance.org/artifacts/post-quantum-cryptography-key-management)  
> 38. What Is Post-Quantum Cryptography (PQC)? A Complete Guide, [https://www.paloaltonetworks.in/cyberpedia/what-is-post-quantum-cryptography-pqc](https://www.paloaltonetworks.in/cyberpedia/what-is-post-quantum-cryptography-pqc)  
> 39. FOIP | Federal Operational Intelligence Platform — Mission, [https://foipmission.com/](https://foipmission.com/)  
> 40. Cryptographic Discovery Methods Compared: Finding Every, [https://www.qcecuring.com/blog/cryptographic-discovery-methods-compared](https://www.qcecuring.com/blog/cryptographic-discovery-methods-compared)  
> 41. Empowering CIOs to accelerate crypto-agility with IBM Quantum, [https://www.ibm.com/new/product-blog/empowering-cios-to-accelerate-crypto-agility-with-ibm-quantum-safe-explorer](https://www.ibm.com/new/product-blog/empowering-cios-to-accelerate-crypto-agility-with-ibm-quantum-safe-explorer)  
> 42. OWASP ASVS 5.0 Standard Release | PDF | Cryptography \- Scribd, [https://www.scribd.com/document/887897879/OWASP-Application-Security-Verification-Standard-5-0-0-En](https://www.scribd.com/document/887897879/OWASP-Application-Security-Verification-Standard-5-0-0-En)

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAAaCAYAAABVX2cEAAAA5ElEQVR4XmNgGAWDCsgD8UEg/grE/6H4LBCrQuVnI4m/h6plgcrhBMoMEA23gZgJSVwKiJ8AcRyaOEGwjgFiYACUzw7EG4HYHK6CBODEADFsHxBzAfEaILZGUUEiuMoAMfAQELuiyZEMchkghq1HlyAVsAHxWiD+BMQ/gVgIVZp4ADMoHoj7GSCuy0FRQSQAxdpqIA6G8jUYIIZdZiAxObAyQMLHA018JwPEwAg0cZxAjAFiUC+6BBAEMUAMO48ugQ5CgPgMEP9igGh4CcQ2SPKgsAJlHVg2OgnEU5HkR8EoGLoAADyKL3KLGYd2AAAAAElFTkSuQmCC>

[image2]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABEAAAAZCAYAAADXPsWXAAAAv0lEQVR4XmNgGAU0A3ZAvBuIXwHxfyD+BcRHgJgNWREQXGGAyP8G4tNAbI8qDQHRDBBFW9EloCAAiC8AsQq6BDLgBOL3DBCXiKLJaQLxXiziWMFMBohrMpHExBkg3pVAEsMLbBkghhyE8jmAeAsQK8AUEAtuMEAM0gHijUCshypNHKhngBjyBIgdUKWIB4EMEEOa0CVIAZcZILHEhC5BLJBhgLhiPboEMcCJARKN5xkghoBSL4hvjqxoFIyCAQcA738kI17y1Z8AAAAASUVORK5CYII=>

[image3]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAZCAYAAAA4/K6pAAAAyElEQVR4XmNgGAU0AdlA/B+IfwHxSSDejYR/QuVK4KqxgB1AfAKIZdDEexggmieiiaMAKSC+CsQ8aOIVDBDNs4CYEU0OBaQCcTqaWCIDRPMiIGZCk8MAsgyoityB+DcQrwRiZiRxooAuEH8A4m1AzIImRxAoA/FjIN4DxJxocgQBKPTvAPExBtTA5ADidUh8DMALxGehWAhNTgKI7wOxOJo4HICcCXIuyGZRJHGQQRFAfAuItyKJY4BVDJCowofj4apHwSigNgAAD6cpBrrbS/0AAAAASUVORK5CYII=>

[image4]: <data:image/png;base64,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>

[image5]: <data:image/png;base64,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>

[image6]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADcAAAAZCAYAAACVfbYAAAACL0lEQVR4Xu2WS0hVURSGfzHTgpCigYrRwCR6SANt0CBEJ9FjYAMn0aCXENEgAkHS4FJBiKkQKRRFz0ENmghK5KCJIjUMEbIGIogQQVCgSET9i7W7nLPuudd98IIN9gff4PzrPPY+e5+9DxAIBIpAFX1E39H3tCNe9ucNvWLDdWQ7/UgvueMd9DPN/DvBlyP0D/1KN5laMZEG99J9tpBAP7RzUS7Sb7TM5HkpoVN0BNrB6/FyUaijA/QuPWBq+Zijr0zWCm3jYZPn5TwdpjvpMv0JnQLFQBpzn16Djpov8q1JJ+TaKI0u7zF5IhvpF1rrju9BL36QPSM9G+g5+pyegT4jLU3Qdkh7ojS4/LHJE7lM+yLH1XSJrtBdkdyHcnqCPqHH46XUNCO5c3td/sLkOVTQaeROlztI8XYc26CLkYy4fMNr5RCSO7fH5U9NnoMs+zdsCO3sD/oL6UavnX6gM/QCUqxoCeyGdmLI5PtdPmjyGDJqsmdU2oLjNvQmz2zBgxb6kn6iZ2lpvOyFvGB5vmzgUQ66vOCK3km7bRhBbv4dOnr1puZLDb0J3WZOIf10naWvTXYU2rljJs+yGfqtbbEFQwae83sV5Hmy+Y5Cf59k1vhwCzr60Zcig7KIAlP+Kl2g46s4Ae3cb+g3sFZkesoIjsFvI5eXMEnb3LH8Oclons6eYZA9aB7a6DQ+lIvXAVmFu6Dbi6zEJ2PVQKAgW+lb5H63+ZR/xEAgEPg/+QsYl3pyMkj6gAAAAABJRU5ErkJggg==>

[image7]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADcAAAAZCAYAAACVfbYAAAACKklEQVR4Xu2WTUgVURiG3yDFAhFUwkQJw5C0VhrhQgU3lW5s46pdiREtQggECyQCFxURqZQoabRpIUELMVq0KUIRhKyF1SICCSIICoyQqPfjO11mvvs353bJzXngWcz7zZ17zpy/AQKBQBGooTP0GV2iA/FychbpBRtuI9X0FT3nruvpOzr694akHKO/6We6y9S2ixvQzkU5S7/QEpNnZQd9SR9DO3g5Xk5EJX1Dz0CfVww+0Icm64a2scPkWTlNJ+k++oN+h04BXxqg62OZdpqaL7LWpBN3Td7q8ksmz0gpfU/r3PU49MdTqTv8OUofQd/6QVNLShu0HdKeKIddfs/kGTlPr0Wu99JN+pM2RvJCkJkgz5aGSGN96ELmzjW7/IHJ0yijr6G7UpTr8Hg7CZAXdpsu0F5Ty0Y7MndOZoLkcyZPQ7b9KzaEdvYb3cK/j16UKnqVrtEWU7M0QTsxYfJDLr9p8hgyanJmVNiCYwz6kPu2UCA76SB0B5QptSdWTUdesPy/bFBRjrg8545+kY7YMII8/Ct09A6Ymg9yLPTTVego+DzrLZ032Qlo53pMnmI3dK2V24JhFAnndxZkfb2gt2itqSVBpvA64uemDMon5DjEh+gGfZrH59DO/YKugaQcp0+gZ5ScfYUiS0deTp+7li8nGc1TqTsMMvc/Qhvt47T8OA+yHlagndpvaoUiXz7DdBZ69p6MVf8TskbvoLi7ayAQCAQCPvwBPAl0lvtdLc0AAAAASUVORK5CYII=>

[image8]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADwAAAAaCAYAAADrCT9ZAAAByUlEQVR4Xu2WTShFQRTHT76/QpSFxEJKKSuhsFHK0mdZCBs7lpSt2CjJwoa9kq/siHztFFnIAjvZ2FDKghL/cea6c0/p3Tf3LrzMr3697jlz555z35t5Q+RwOBwpTBU8ga/wU3sBa3R+xYg/67EZOheWCVgvgwkohPvwhvznX8JGcxBY0jnlLRwPpn+nmvimO5hmxMvhAxwS8WSYhs0yGJJK8l92lsgpKuA97JSJMGwRT96lr7PhDmz6GWHHDNk3rNglrqtbxPPhAUWor5144kOYBzdgS2CEHbMUreFB4rpWjVg6XINtRsyKa+LJT2GHyNkSteEc+ATfYJGOLZLlz1iiFr1qeFsmIhC1YcUycV0jcE5/RkZtCpvwhfhtlgTTCeknf8cM4zss+L4zMd5ye4RTImeF1+wwXCCefCwwwp44vuFi4pqORdwKtRuvw159XUs8+RXZ/xWZxNGwqk3VNCkTyZJJvF7lBrBH/IABEbchjoa9A0aDTCRDGXGz8zIBeogfoE43UYmjYXXiUju11S+uD54TbxreRtBq5NXaVScbb3M5I37Dttg2XEp8vDwiruNDX4+ag/4itg2nLHUwVwYdDofD4fiHfAHhdmqp//6cewAAAABJRU5ErkJggg==>

[image9]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHUAAAAWCAYAAAD+ZNNIAAABiElEQVR4Xu2YvytFYRjHHz9DhJJSZCFltZgMFonNQtkMDIrIIJEsBgaDDFJiuZti8mswiH/AxqQsFkWRJL6vRzrvw809nHOQ76c+w3m+513ue5/3fe4VIYQQQkgSbMNhWyR/lzb4BC9hockyoQIuwGYbkJ8hCx7DLdGNnfTjjCmF4zAFO0xGEqYPLsFaeAdvYI33RjgK4ADcgL0wz49J3OTDM1j9+rwo2q3Lb298nRzYI3oCjMJiPyZxMQjnAs9V8Bbew7pA/bu0i3buFCwzGYkQd0yeiA45QeZFu3XV1KNgSPR4b7EBiQb382XGFkU3+Ro+SHTd2gp34Cnsh7l+TKLAdan7gN3E+hGzot26boOQdMIjuA+7Re9ZEhNjcMIWA7huvRLt1nqTZYLrzAPRwavRj0gcFInepSU2MEyLduuaqacjG3bBTdFjvdKPSZyMwAu494mHopv6CBteVqbHdbb7m9FN0+5LQxLEDSjnopsVxhW3mBBCyG+jHO7K+3s5nU26jBBC/gPPBhdQl82tzuYAAAAASUVORK5CYII=>

[image10]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGwAAAAWCAYAAAAl33lqAAABhElEQVR4Xu2YvytGURzGv36GCCWlyELKajEZLBKbhbIZGBSRQSJZDAwGGaTE8m6Kya/BIP4BG5OyWBRFkniOr3TPl9t7731vkZ5PfYZ7nnuWe97nnNMrQgghhPxP9uG4HSR/ky74Bm9hqcmiUANXYLsNSPrkwXO4J7pos34cmUo4DTOwx2QkRYbgGmyET/ABNnhvxKMEjsAdOAiL/JjkQjG8gvWfz6uiLVv/eiM5BXBAtLmTsNyPSRJG4VLguQ4+wmfYFBjPlW7Rxs3BKpORiLit60L0whBkWbRlm2Y8DcZEt9wOG5DsuCv8gh0UXcB7+CLptawTHsBLOAwL/Zhkw7XLfTx3s/uJRdGWbdsgJr3wDB7DftFzjSRgCs7YwQCuZXeiLWs2WRRco05ELzGtfkTiUiZ6dlXYwDAv2rItMx5GPuyDu6Jbba0fk6RMwBt4lMVT0QV7hS0fM8NxjXR/bblbp/tBkJRwh/216ELEccNNJoQQEoVqeCjfz8Ew23QaIYT8Fu8m3FCX2Gw8DgAAAABJRU5ErkJggg==>

[image11]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAKQAAAAWCAYAAABOtzc/AAADP0lEQVR4Xu2ZS6hNURzG//J+F/LIq0SSRwaUAQPlkchQyeuWTLgDeQ5QXiVRJpL3DQMMPSODO6AQyQARSR4pE6FIEt93/+ew9v+evc/e+7zvXr/6Budb67zW+tb/rLWOiMfj8Xg8Hk/d0h8aYE1P/XMDWm/NBqUTNA5aAz2DNgSbI1kEDbamp7rMh/5An6Cepq2e6AydtmYBLkJ3oHOi3ytJIG9Ck6xZBWZAa62ZRVhN7kKXRSdvR7C5rugKXbFmBJzkJIEcCH2R2gRyDrTFmllkNXQEGg39gL5BIwM96ofuUrlAcmGeEO1fi0DOEx9I6Qa9gkbkHh8WnZDj/3rE55BooH9CT0Und1igx3+2WyMmPaRygXwn2teVfa/h0BnoEXQbugANCfRID7dNmQ9kM3TAecwAfRcN1VjHL8ZSqBVaIFrFWGF2Qe+hJU4/Ml10b5eGSgaScA8XViHHiH6fJsfj9ua1lOcUn/lAcnKfQIOMf1B0UlqMH8UxqK81wUzoOXRftGJeh96ITm4aahnI86KV0aUL9BE6afw0ZD6QvOLZbU3RgH6Ffkn8KjnVGg6cNFZOVpPlUJ9gcyiPpf1PaJT26NMC5AO50TaEEBbI3jm/xfjkFvTZmhEMlfafvZjmtj2zA8NK81L00rgQ+0QH4qxtiICDdg26JBoADnwYC60Rk7QVstRATs75p4xProq2cX9ZCpmukJuhbdZ0YJXkqmeV5AVzMUZBL6C9oqdF7k0fQKtET68uvEtMEnSXtIHcZBtCsIHke7E6co9Inz/bllbRceplGxKS2UBy4Lh3LLTnc9kpOgk8VRZjPzTBeKy+3BLwgnqx6FVSP9EDzTKnXxLSBpILMA78Z4f9p+Qe898rLiDCC3NuI1y42N6K7o1LJbOB5Ab/g+jeJ0oMEifnNzS+7ZnhbLWGA6sNX4+v9RBaGWxORNJAzhZ9X57445APcJPoJfk9p41jwHFb4XjrRC/SJzpeWjIZSB4wuKI56ElUjlNkOYgbSB7YeBfKxZT/DlwMR91OIbAPr734H/gs08ZDHvfJrJS87uFCy1fTUslkIBuduIFsRHwgG5Rp1uggcM8d5wDp8Xg8Ho/HU03+AkCaz/N5A518AAAAAElFTkSuQmCC>

[image12]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAWCAYAAACG9x+sAAABcklEQVR4Xu2UTSsGURTH//ISIpG8lLcF+QK+gy1lYyeSlIWULCSykUgWspASH8HqKWWlCEWyY6VsbBRFkvgf56G5p5h5Zu6zkPnVbzHnP1Nz77n3ACkpKb+RoeO2+Ffopu/0jpaZzCeFtIe22CAJBfSQ7kIXMePGXiihI/SEztJ6N07GEF2nrfSZPtJm5434FNNRek4XaYMbJ0d25po2ZZ/XoF3Y+H4jHnJUhukpnaIVbuyPMboUeG6kT/SFtgfqUZHj2EePoTte48Z+KaWXtNbUl6Fd2DL1MGQQ7EM3pM5keUFG5rwtQhf0QF8RvQvV0F3fgecL+hOy+1e0ygZZFqBdkB+KihyffnpBV5DnhUzSaVsMIF24h3ahw2RhyOQZoEd0FXqvvFIOPfuVNjDMQbuwbeq50EvPoNPta9IlZoLe0r0QD6ALeKOdn1/GQ0bqIPTIynhuc9IcKaI30B/LxU35OCFytGQhctm7TJaSkvIf+ADcH0pZ0KZ4YAAAAABJRU5ErkJggg==>

[image13]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGcAAAAaCAYAAACq/ULmAAADAklEQVR4Xu2YWcgOURjH//Z9CSFEsqQUyprtQpQLyp7sKblASiiSEBeUcEHhUlmypVwQ2UoiywUS7iRSohSFxP/vmdc38/T5vnnPDEnnV7/e5nlm3vfMec6cc+YFIpFIJBKJRBy96HX6kX5PvEf7JfnDqfj75NzGSS4v6+ggH6yHtvQSfYqa339AR6RPIvuTnHxGV2XTf5VG9BWsLfq8DLsH+SiJv6DtKxfkpQ/s4ue0YSrejb6ki1y8GrbRUT6Yk56oGRhNXU70gN3wZJ/4DdvpMdrbJ0pgHP1KV7h4X1gfvqYDXC43Z2AdMS05bkbP0ZG/zghDHRJaHHEB1q7pLt4KNjqraZ9GtwbaE7qVtsmmC3GALnexLrAn+i0d7HJVMQHWCVdoS3qKjsmcEcYOFCvOAli7jqZi6uQTsNEaQnO6ATZVrqRNsumqaUBvITvlt4N9v576oal4MI9hHXGDTnK5UIoWRx35jn6G3bDYh/xTWV2oM+fS83QNbZ1N50bF6ZU6VrG11nxAOQP8J1pQVZyzPlGAosURh2DtWkJ3JZ9los7VtKlZYyftmk1XzRH6iY73iVC04J6GVVujtEM2XS+zUbNzyuMX5B+plSn3DWw6+pNMpHdgG5kQNHh0b1N8IpRKYRbTPbCO0FxcBmU8Odp+qk3XXLxs+tPjsB3gfJfLw0b6jc5x8U10tIvlQruyk3RmcqztnjriIcK3z2nKKI7apjat94mS6E4Pwhb1eQjbIKyGtVEbmDT6rpuo/VWgTnSh1he/uF6E/ZAWy6KUUZzKy+YwnyiIpm6tMfdhA0BrTwiacdS+pT5BttC9PlgfnWGF2e0TZAbsx7QVLEoZxdE/BdqxlfEki050M2xt0XuPtuahTIW9fK5NxfR9Q2BPo/ox95Q2i96FLVqVRXZsKq+1RnvzysJ9GzZyQwktTkfYdvQqrB2ay3W8LH1SlWim0JOiKXshihVFDEf2r6/a1EvoP0tocf4EelVYgur/H/xvGUhb+GAkEolEIpFIJBKJlMQPdfCp7+bpsrcAAAAASUVORK5CYII=>