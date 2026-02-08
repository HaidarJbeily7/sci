# EU AI Act Probe Mapping Reference

This document provides the academically-grounded mapping between SCI security probes and EU AI Act compliance requirements, based on the COMPL-AI Framework and related academic research.

## 1. Introduction & Academic Sources

The mappings in this document are derived from peer-reviewed academic research that provides authoritative interpretation of EU AI Act technical requirements for Large Language Models (LLMs).

### Primary Sources

1. **COMPL-AI Framework Paper** - ETH Zurich, INSAIT, LatticeFlow AI
   - arXiv: [2410.07959](https://arxiv.org/abs/2410.07959)
   - Provides systematic interpretation of EU AI Act requirements mapped to technical benchmarks

2. **COMPL-AI Technical Interpretation**
   - [compl-ai.org/interpretation](https://compl-ai.org/interpretation)
   - Detailed breakdown of 18 technical requirements across 5 ethical principles

3. **Robustness and Cybersecurity in EU AI Act** - ACM FAccT 2025
   - DOI: [10.1145/3715275.3732020](https://dl.acm.org/doi/10.1145/3715275.3732020)
   - Academic analysis of Article 15 robustness and cybersecurity requirements

4. **Assuring EU AI Act Compliance and Adversarial Robustness**
   - arXiv: [2410.05306](https://arxiv.org/html/2410.05306v1)
   - Framework for adversarial testing aligned with EU AI Act

5. **EU AI Act Official Text**
   - [artificialintelligenceact.eu](https://artificialintelligenceact.eu)
   - Official consolidated text of the regulation

---

## 2. EU AI Act Requirements Taxonomy (COMPL-AI)

The COMPL-AI Framework defines **18 Technical Requirements** across **5 Ethical Principles**:

### Technical Robustness & Safety

| Requirement | Description | Primary Articles |
|-------------|-------------|------------------|
| Robustness & Predictability | Consistent responses under input variations | Art. 15(1), Art. 15(4) |
| Cyberattack Resilience | Resistance to jailbreaks, prompt injection, adversarial manipulation | Art. 15(5), Art. 55(1)(d) |
| Corrigibility | Ability to be corrected and controlled | Art. 15, Art. 14 |

### Privacy & Data Governance

| Requirement | Description | Primary Articles |
|-------------|-------------|------------------|
| Training Data Suitability | Appropriate data quality and relevance | Art. 10(2), Art. 10(3) |
| No Copyright Infringement | Protection of copyrighted training data | Art. 53(1)(c), Art. 53(1)(d) |
| User Privacy Protection | Protection of user data and privacy | Art. 10(5), Art. 53(1)(e) |

### Transparency

| Requirement | Description | Primary Articles |
|-------------|-------------|------------------|
| Capabilities & Limitations | Clear documentation of model capabilities | Art. 13(1), Art. 53(1)(a) |
| Interpretability | Understandable model behavior | Art. 13(1), Art. 14(4) |
| AI Disclosure | Disclosure of AI-generated content | Art. 50(1), Art. 50(2) |
| Traceability | Audit trails and logging | Art. 12, Art. 13(2) |
| Explainability | Explanation of decisions and outputs | Art. 13(1), Art. 14(4)(d) |

### Diversity, Non-discrimination & Fairness

| Requirement | Description | Primary Articles |
|-------------|-------------|------------------|
| Absence of Bias | Freedom from systematic bias | Art. 10(2)(f), Annex IV(2)(g) |
| Absence of Discrimination | Non-discriminatory outputs | Art. 15(4), Art. 10(2)(g) |

### Social & Environmental Well-being

| Requirement | Description | Primary Articles |
|-------------|-------------|------------------|
| Environmental Impact | Energy efficiency and sustainability | Art. 40, Art. 95 |
| Harmful Content Prevention | Prevention of toxic/harmful outputs | Art. 9, Art. 95 |

---

## 3. Attack Category Definitions with Legal Terms

### Cyberattack Categories (Art. 15(5))

The EU AI Act Article 15(5) specifically addresses cyberattack resilience:

> "High-risk AI systems shall be resilient against attempts by **unauthorized third parties** to alter their use, outputs or performance by exploiting system vulnerabilities."

This encompasses:

| Attack Type | Legal Interpretation | Technical Definition |
|-------------|---------------------|---------------------|
| **Prompt Injection** | "Adversarial examples or confidentiality attacks exploiting model flaws" | Injection of malicious instructions to override system behavior |
| **Jailbreaking** | "Attempts to alter use or outputs" via manipulation | Circumvention of safety guardrails through crafted prompts |
| **Model Evasion** | "Exploiting system vulnerabilities" | Techniques to bypass detection or safety measures |
| **Data Poisoning** | Altering model performance through training manipulation | Corruption of training data to influence outputs |

### Data Governance Categories (Art. 10, Art. 53)

| Attack Type | Legal Interpretation | Technical Definition |
|-------------|---------------------|---------------------|
| **Data Extraction** | Violation of Art. 10 data governance requirements | Unauthorized disclosure of training or user data |
| **Training Data Leakage** | Art. 53(1)(c) copyright protection requirements | Extraction of copyrighted training content |
| **PII Disclosure** | Art. 10(5) privacy protection requirements | Leakage of personally identifiable information |

### Fairness Categories (Art. 15(4), Annex IV)

| Attack Type | Legal Interpretation | Technical Definition |
|-------------|---------------------|---------------------|
| **Bias Detection** | Art. 10(2)(f) examination of biases | Identification of systematic demographic biases |
| **Discrimination Testing** | Annex IV(2)(g) bias examination documentation | Testing for discriminatory outputs |

### Safety Categories (Art. 9, Art. 95)

| Attack Type | Legal Interpretation | Technical Definition |
|-------------|---------------------|---------------------|
| **Toxicity Generation** | Art. 9 risk management + Art. 95 societal well-being | Generation of harmful, offensive, or toxic content |
| **Malware Generation** | Art. 15(5) confidentiality attacks | Generation of malicious code or attack vectors |

---

## 4. Complete Probe-to-Article Mapping Table

### Primary Mappings

| SCI Probe Category | Primary Article(s) | COMPL-AI Requirement | Legal Basis |
|-------------------|-------------------|---------------------|-------------|
| `prompt_injection` | Art. 15(5) | Cyberattack Resilience | "resilient against adversarial examples and input manipulation" |
| `jailbreak` | Art. 15(5), Art. 55(1)(d) | Cyberattack Resilience | "internal/external adversarial testing including red teaming" |
| `jailbreak_encoding` | Art. 15(5) | Cyberattack Resilience | "model evasion attacks" via encoding obfuscation |
| `extraction` | Art. 10, Art. 53(1)(c) | User Privacy / No Copyright | "data governance" + "copyrighted training data" |
| `leakage` | Art. 10(5), Art. 53(1)(e) | User Privacy Protection | "privacy and data protection" requirements |
| `bias` | Art. 15(4), Annex IV(2)(g) | Absence of Bias/Discrimination | "appropriate for intended purpose" + "bias examination" |
| `toxicity` | Art. 9, Art. 95 | Harmful Content Prevention | "risk management system" + "social well-being" |
| `manipulation` | Art. 15(5) | Cyberattack Resilience | "attempts to alter outputs" |
| `hallucination` | Art. 13(1), Art. 15(1) | Accuracy / Interpretability | "appropriate level of accuracy" |
| `transparency` | Art. 13, Art. 50 | AI Disclosure / Capabilities | "transparency and information provision" |
| `human_oversight` | Art. 14 | Corrigibility | "human oversight requirements" |
| `web_injection` | Art. 15(5) | Cyberattack Resilience | "model evasion attacks" via output injection |

### Garak Module Mapping

| Garak Module | SCI Category | Primary Article(s) | Requirement |
|--------------|--------------|-------------------|-------------|
| `promptinject` | prompt_injection | Art. 15(5) | Cyberattack Resilience |
| `dan` | jailbreak | Art. 15(5), Art. 55(1)(d) | Cyberattack Resilience |
| `encoding` | jailbreak_encoding | Art. 15(5) | Cyberattack Resilience |
| `leakreplay` | extraction | Art. 10, Art. 53(1)(c) | User Privacy / No Copyright |
| `malwaregen` | manipulation | Art. 15(5) | Cyberattack Resilience |
| `atkgen` | atkgen | Art. 15(5) | Cyberattack Resilience |
| `continuation` | toxicity | Art. 9, Art. 95 | Harmful Content Prevention |
| `donotanswer` | toxicity | Art. 9 | Harmful Content Prevention |
| `gcg` | jailbreak | Art. 15(5) | Cyberattack Resilience |
| `glitch` | jailbreak | Art. 15(5) | Cyberattack Resilience |
| `goodside` | baseline | N/A | Baseline testing |
| `lmrc` | toxicity | Art. 9, Art. 95 | Harmful Content Prevention |
| `misleading` | hallucination | Art. 13(1), Art. 15(1) | Accuracy |
| `packagehallucination` | hallucination | Art. 13(1), Art. 15(1) | Accuracy |
| `realtoxicityprompts` | toxicity | Art. 9, Art. 95 | Harmful Content Prevention |
| `snowball` | hallucination | Art. 13(1), Art. 15(1) | Accuracy |
| `web_injection` | web_injection | Art. 15(5) | Cyberattack Resilience |

---

## 5. Garak Probe Classification by Requirement

### Cyberattack Resilience (Art. 15(5))

Probes testing resistance to adversarial manipulation:

```
promptinject.HijackHateHumans
promptinject.AutoDAN
promptinject.HumanJailbreaks
dan.DAN
dan.DUDE
dan.DANJailbreak
encoding.InjectBase64
encoding.InjectHex
encoding.InjectROT13
encoding.InjectMorse
gcg.GCGCached
glitch.Glitch
malwaregen.Evasion
malwaregen.Payload
malwaregen.SubFunctions
atkgen.Tox
web_injection.MarkdownImageExfil
```

### User Privacy / Data Governance (Art. 10, Art. 53)

Probes testing data protection and privacy:

```
leakreplay.LiteratureCloze
leakreplay.GuardianCloze
```

### Harmful Content Prevention (Art. 9, Art. 95)

Probes testing toxic/harmful content generation:

```
continuation.ContinueSlursReclaimedSlurs
donotanswer.DiscriminationExclusionToxicityHatefulOffensive
lmrc.Bullying
lmrc.Deadnaming
lmrc.QuackMedicine
lmrc.SexualContent
lmrc.Sexualisation
lmrc.SlurUsage
realtoxicityprompts.RTPSevere_Toxicity
```

### Accuracy / Interpretability (Art. 13(1), Art. 15(1))

Probes testing factual accuracy and reliability:

```
misleading.FalseAssertion50
packagehallucination.Python
snowball.GraphConnectivity
snowball.Primes
snowball.Senators
```

### Baseline Testing (No specific article)

```
goodside.Tag
goodside.WhoIsRiley
```

---

## 6. Compliance Evidence Guidelines per Article

### Article 15(5) - Cyberattack Resilience

**Evidence Requirements:**
- Documentation of adversarial testing methodology
- Results of prompt injection resistance testing
- Jailbreak attempt success/failure rates
- Red teaming exercise reports

**Acceptable Probe Types:**
- Prompt injection probes
- Jailbreak probes (DAN, encoding-based)
- Gradient-based attack probes (GCG)
- Output manipulation probes (web_injection, malwaregen)

### Article 10 - Data Governance

**Evidence Requirements:**
- Training data provenance documentation
- Data extraction resistance testing
- Privacy protection verification

**Acceptable Probe Types:**
- Data leakage probes
- Training data extraction probes
- PII detection probes

### Article 53(1)(c) - Copyright Protection

**Evidence Requirements:**
- Copyright compliance documentation
- Training data content disclosure testing

**Acceptable Probe Types:**
- Literature cloze probes
- Training data memorization probes

### Article 9 - Risk Management

**Evidence Requirements:**
- Risk assessment documentation
- Harmful content generation testing
- Toxicity level measurements

**Acceptable Probe Types:**
- Toxicity probes
- Harmful content generation probes
- Content moderation bypass probes

### Article 13 - Transparency

**Evidence Requirements:**
- Model capability documentation
- Accuracy assessment results
- Limitation disclosure

**Acceptable Probe Types:**
- Hallucination probes
- Factual accuracy probes
- Misleading content probes

### Annex IV(2)(g) - Bias Examination

**Evidence Requirements:**
- Bias testing methodology documentation
- Demographic fairness assessments
- Discrimination testing results

**Acceptable Probe Types:**
- Bias detection probes
- Demographic parity probes
- Fairness assessment probes

---

## 7. References & Citations

### Academic Papers

1. Guldimann, P., et al. (2024). "COMPL-AI Framework: A Technical Interpretation and LLM Benchmark for the EU Artificial Intelligence Act." *arXiv:2410.07959*. ETH Zurich, INSAIT, LatticeFlow AI.

2. Casper, S., et al. (2024). "Black-Box Access is Insufficient for Rigorous AI Audits." *arXiv:2401.14446*. MIT.

3. Bhatt, U., et al. (2025). "Robustness and Cybersecurity in the EU AI Act." *ACM FAccT 2025*. DOI: 10.1145/3715275.3732020.

4. Bieringer, L., et al. (2024). "Assuring EU AI Act Compliance and Adversarial Robustness of LLMs Using Guardrails." *arXiv:2410.05306*.

### EU AI Act References

- **Article 9**: Risk Management System
- **Article 10**: Data and Data Governance
- **Article 13**: Transparency and Provision of Information
- **Article 14**: Human Oversight
- **Article 15**: Accuracy, Robustness, and Cybersecurity
- **Article 50**: Transparency Obligations for Certain AI Systems
- **Article 53**: Obligations for Providers of General-Purpose AI Models
- **Article 55**: Obligations for Providers of General-Purpose AI Models with Systemic Risk
- **Article 95**: Penalties
- **Annex IV**: Technical Documentation for High-Risk AI Systems

### Official Resources

- EU AI Act Official Text: [artificialintelligenceact.eu](https://artificialintelligenceact.eu)
- COMPL-AI Framework: [compl-ai.org](https://compl-ai.org)
- Garak LLM Vulnerability Scanner: [github.com/NVIDIA/garak](https://github.com/NVIDIA/garak)
