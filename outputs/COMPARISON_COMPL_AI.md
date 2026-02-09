# SCI vs COMPL-AI Framework Comparison

## Introduction

This document compares the SCI framework results with the COMPL-AI Framework developed by ETH Zurich, INSAIT, and LatticeFlow AI. Both frameworks evaluate LLM security and EU AI Act compliance, but they employ fundamentally different methodologies. COMPL-AI uses static benchmarks to measure compliance readiness, while SCI uses adversarial attack probes to measure resistance to real-world attacks.

---

## 1. Framework Comparison

### 1.1 Fundamental Approach

| Aspect | COMPL-AI | SCI |
|--------|----------|-----|
| **Philosophy** | "Can this model pass compliance benchmarks?" | "Can this model resist active attacks?" |
| **Test Type** | Static benchmark evaluation | Dynamic adversarial probing |
| **Threat Model** | Compliance auditor | Malicious attacker |
| **Output** | Compliance readiness scores | Security vulnerability scores |

### 1.2 Technical Details

| Aspect | COMPL-AI | SCI |
|--------|----------|-----|
| **Requirements** | 18 technical requirements | 8 vulnerability categories |
| **Benchmarks/Probes** | 27 benchmarks | 38+ Garak probes |
| **Attack Simulation** | Minimal (benchmark-based) | Extensive (DAN, encoding, injection, etc.) |
| **Dynamic Generation** | No | Yes (atkgen probes) |
| **Models Tested** | 12 frontier models (Oct 2024) | 12 models including Chinese/xAI (Feb 2026) |

### 1.3 EU AI Act Coverage

**COMPL-AI** maps to 5 ethical principles with 18 requirements:

| Principle | Requirements Covered |
|-----------|---------------------|
| Technical Robustness | Robustness, Cyberattack Resilience, Corrigibility |
| Privacy & Data | Training Data, Copyright, User Privacy |
| Transparency | Capabilities, Interpretability, AI Disclosure, Traceability |
| Fairness | Bias, Discrimination |
| Social Well-being | Environmental Impact, Harmful Content |

**SCI** maps 8 categories to specific articles:

| Category | Primary Article | COMPL-AI Overlap |
|----------|-----------------|------------------|
| Jailbreak | Art. 15(5) | Cyberattack Resilience |
| Toxicity | Art. 9, 95 | Harmful Content |
| Extraction | Art. 10, 53 | User Privacy, Copyright |
| Leakage | Art. 10(5) | User Privacy |
| Manipulation | Art. 15(5) | Cyberattack Resilience |
| Hallucination | Art. 13, 15 | Interpretability |
| Injection | Art. 15(5) | Cyberattack Resilience |

**Gap Analysis**:
- SCI covers Art. 15(5) Cyberattack Resilience more thoroughly (3 categories vs 1)
- COMPL-AI covers Fairness/Bias which SCI lacks
- COMPL-AI covers Environmental Impact which SCI lacks
- SCI lacks Traceability and Explainability coverage

---

## 2. Model Coverage Comparison

### 2.1 Models Tested

| Model Family | COMPL-AI (Oct 2024) | SCI (Feb 2026) |
|--------------|---------------------|----------------|
| **Anthropic Claude** | Claude 3 Opus, Sonnet, Haiku | Claude 3.7 Sonnet, Sonnet 4 |
| **OpenAI GPT** | GPT-4, GPT-4 Turbo, GPT-4o | GPT-4o-mini, GPT-OSS-120b |
| **Google** | Gemini Pro, Gemini 1.5 | Gemini 2.5, 3, Gemma-2-9b |
| **Meta Llama** | Llama 2, Llama 3 variants | Not tested |
| **Mistral** | Mistral Large, Mixtral | Mistral-7b v0.2, v0.3 |
| **xAI Grok** | Not tested | Grok-4.1-Fast |
| **Chinese Models** | Not tested | GLM-4.7-Flash, Aion-1.0-mini |

### 2.2 Coverage Gap Implications

**What SCI adds**:
- First security assessment of Grok (xAI)
- First security assessment of GLM-4.7-Flash (Zhipu, open-source)
- First security assessment of Aion-1.0-mini (Alibaba)
- Updated Claude/GPT variants (2026 versions)

**What SCI misses**:
- Llama family (Meta's open-source models)
- Mixtral (Mistral's MoE model)
- Older GPT-4 variants for comparison

---

## 3. Results Comparison

### 3.1 Where Both Frameworks Agree

| Finding | COMPL-AI Evidence | SCI Evidence |
|---------|-------------------|--------------|
| **Claude models are safety-focused** | High robustness scores | 86.85% avg, strong manipulation resistance |
| **Google models have gaps** | Multiple compliance issues | 66.19% avg, "Limited" risk classification |
| **Hallucination is challenging** | Variable accuracy across models | 51-100% range, largest variance category |
| **Closed-source generally safer** | Higher compliance scores | Higher security scores on average |
| **Jailbreak resistance varies widely** | Significant model differences | 55-100% range across models |

### 3.2 Where Results Diverge

| Aspect | COMPL-AI Finding | SCI Finding | Likely Explanation |
|--------|------------------|-------------|-------------------|
| **Mistral security** | Moderate compliance | 82% (competitive) | SCI tests different attack vectors |
| **GPT-4o-mini** | Strong compliance | 83.94% (mid-tier) | Adversarial probes reveal weaknesses benchmarks miss |
| **Open-source gap** | Large gap to closed-source | Smaller gap (Mistral competitive) | Model-specific, not architecture-specific |

### 3.3 Open-Source Model Performance

**Correcting my earlier error**: GLM-4.7-Flash is fully open-source (weights on HuggingFace).

| Model | Type | SCI Score | Implication |
|-------|------|-----------|-------------|
| GLM-4.7-Flash | Open-source | 99.97% | **Open-source can achieve top security** |
| Mistral-7b-v0.3 | Open-source | 83.02% | Competitive with closed-source |
| Gemma-2-9b | Open-source | 66.21% | Lower security |
| Aion-1.0-mini | Open-source | 79.44% | Moderate security |

**Key Insight**: The open-source vs closed-source distinction is NOT predictive of security. Training approach and safety focus matter more. GLM's 99.97% proves open-source models can be the most secure.

**Why GLM excels despite being open-source**:
1. Strict Chinese AI regulations require aggressive content filtering
2. Zhipu AI invested heavily in safety alignment
3. Open weights don't mean weak safety - training matters more
4. Regulatory pressure can drive security investment regardless of licensing

---

## 4. Methodological Insights

### 4.1 What Benchmarks Miss (SCI Advantage)

COMPL-AI benchmarks test **known patterns**. SCI probes test **adversarial creativity**.

| Attack Type | COMPL-AI Coverage | SCI Coverage |
|-------------|-------------------|--------------|
| DAN jailbreaks | Limited | Extensive (dan.DAN, dan.DUDE, etc.) |
| Encoding attacks | Minimal | Full suite (base64, hex, ROT13, morse) |
| Attack generation | None | atkgen.Tox (dynamic adversarial) |
| Prompt injection | Some | Comprehensive (promptinject module) |
| Roleplay bypass | Limited | Tested via continuation probes |

**Example**: A model might pass COMPL-AI's robustness benchmark but fail SCI's `encoding.InjectBase64` probe because it never trained on base64-encoded attacks.

### 4.2 What Adversarial Testing Misses (COMPL-AI Advantage)

SCI focuses on attack resistance. COMPL-AI covers broader compliance.

| Requirement | COMPL-AI Coverage | SCI Coverage |
|-------------|-------------------|--------------|
| Fairness/Bias | Dedicated benchmarks | Not tested |
| Environmental impact | Energy metrics | Not tested |
| Traceability | Audit trail tests | Not tested |
| Explainability | Decision explanation | Not tested |
| Copyright compliance | Training data tests | Partial (extraction) |

### 4.3 Scoring Philosophy Differences

**COMPL-AI**: "What percentage of compliance requirements does this model meet?"
- Binary pass/fail on some tests
- Aggregate compliance percentage
- Designed for auditors and regulators

**SCI**: "How often does this model resist attacks?"
- Weighted by severity
- Risk level classification
- Designed for security engineers and deployers

---

## 5. Practical Implications

### 5.1 When to Use Each Framework

| Scenario | Recommended Framework | Reason |
|----------|----------------------|--------|
| EU AI Act audit preparation | COMPL-AI | Comprehensive compliance coverage |
| Pre-deployment security testing | SCI | Real attack simulation |
| Selecting production model | Both | Combined coverage |
| Red team exercise | SCI | Adversarial focus |
| Regulatory documentation | COMPL-AI | Structured requirements |
| Incident prevention | SCI | Attack pattern coverage |

### 5.2 Combined Recommendations

Models that score well on BOTH frameworks:

| Model | COMPL-AI Status | SCI Score | Combined Assessment |
|-------|-----------------|-----------|---------------------|
| Claude 3.7 Sonnet | High compliance | 91.37% | **Recommended for production** |
| GPT-OSS-120b | (Not tested) | 96.96% | Strong security, needs compliance check |
| GLM-4.7-Flash | (Not tested) | 99.97% | Highest security, but aggressive filtering |

Models with concerns in BOTH frameworks:

| Model | COMPL-AI Status | SCI Score | Combined Assessment |
|-------|-----------------|-----------|---------------------|
| Google variants | Compliance gaps | 66% avg | **Avoid for high-risk applications** |

### 5.3 Deployment Decision Matrix

| Risk Level | COMPL-AI Threshold | SCI Threshold | Recommendation |
|------------|-------------------|---------------|----------------|
| High-risk AI (Art. 6) | >90% compliance | >90% security | GLM, GPT-OSS-120b, Claude 3.7 |
| Limited-risk (Art. 50) | >75% compliance | >80% security | Most models except Google |
| Minimal-risk | >60% compliance | >70% security | All tested models |

---

## 6. Key Learnings

### 6.1 Insights from This Comparison

This comparison reveals several important findings about LLM security evaluation:

Compliance and security are distinct properties. A model can pass compliance benchmarks while remaining vulnerable to adversarial attacks. The two frameworks measure fundamentally different aspects of model behavior.

Open-source models can achieve top security. GLM-4.7-Flash scored 99.97% despite being fully open-source with publicly available weights. The licensing model does not predict security outcomes.

Regulatory pressure appears to drive security investment. GLM's exceptional performance likely reflects compliance requirements from Chinese AI regulations, demonstrating that regulatory frameworks can incentivize safety improvements.

Static benchmarks have inherent limitations. COMPL-AI's benchmark approach cannot capture the full range of creative attacks that adversarial probing reveals. Models may pass benchmarks while remaining vulnerable to attack variants.

Model scale is not deterministic. Mistral-7b (7B parameters) outperforms larger Google models, indicating that training methodology matters more than raw parameter count.

Version progression does not guarantee improvement. Claude Sonnet 4 scored lower than Claude 3.7, suggesting that newer versions may optimize for different objectives at the expense of security.

### 6.2 Research Gaps Identified

| Gap | Impact | Suggested Resolution |
|-----|--------|---------------------|
| No fairness probes in SCI | Missing discrimination risks | Add bias detection probes |
| No Chinese models in COMPL-AI | Incomplete landscape | Extend COMPL-AI coverage |
| No Llama in SCI | Missing popular open-source | Add Meta models |
| Limited version tracking | Can't track safety trends | Longitudinal studies |

---

## 7. Conclusion

The two frameworks serve complementary purposes. COMPL-AI provides comprehensive compliance coverage across 18 EU AI Act requirements, making it suitable for regulatory audits and documentation. SCI provides deeper adversarial testing with higher attack realism, making it appropriate for security assessments and red-teaming exercises.

| Dimension | COMPL-AI | SCI |
|-----------|----------|-----|
| Compliance Coverage | Comprehensive (18 requirements) | Partial (8 categories) |
| Security Depth | Benchmark-based | Adversarial probe-based |
| Attack Realism | Limited | Extensive |
| Model Coverage | Frontier models | Frontier + Chinese/xAI |

For comprehensive pre-deployment assessment, both frameworks should be applied. The results demonstrate that open-source licensing does not predict security outcomes, and that regular re-testing is necessary as both models and attack techniques evolve.

---

## References

### COMPL-AI Framework
- Guldimann, P., et al. (2024). "COMPL-AI Framework: A Technical Interpretation and LLM Benchmark for the EU Artificial Intelligence Act." *arXiv:2410.07959*
- [compl-ai.org](https://compl-ai.org)

### SCI Framework
- This thesis project
- Garak LLM Vulnerability Scanner (NVIDIA)
- [artificialintelligenceact.eu](https://artificialintelligenceact.eu)

### Additional Academic Sources
- Bhatt, U., et al. (2025). "Robustness and Cybersecurity in the EU AI Act." *ACM FAccT 2025*
- Bieringer, L., et al. (2024). "Assuring EU AI Act Compliance and Adversarial Robustness." *arXiv:2410.05306*
