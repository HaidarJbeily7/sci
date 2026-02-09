# Extending COMPL-AI with the SCI Score

## Introduction

The COMPL-AI Framework (ETH Zurich, INSAIT, LatticeFlow AI) provides a systematic approach to evaluating LLM compliance with EU AI Act requirements. However, its reliance on static benchmarks leaves a gap in assessing real-world attack resistance. This document proposes adding the SCI Score as a new metric within COMPL-AI to address this limitation.

## 1. The Gap in Current COMPL-AI Methodology

### 1.1 COMPL-AI's Strengths

COMPL-AI provides valuable coverage of EU AI Act requirements:

| Ethical Principle | Requirements Covered | Articles Mapped |
|-------------------|----------------------|-----------------|
| Technical Robustness | Robustness, Cyberattack Resilience, Corrigibility | Art. 15, Art. 14 |
| Privacy & Data | Training Data, Copyright, User Privacy | Art. 10, Art. 53 |
| Transparency | Capabilities, Interpretability, AI Disclosure | Art. 13, Art. 50 |
| Fairness | Bias, Discrimination | Art. 10, Annex IV |
| Social Well-being | Environmental Impact, Harmful Content | Art. 40, Art. 9 |

### 1.2 The Adversarial Testing Gap

COMPL-AI's Cyberattack Resilience requirement (Art. 15(5)) is assessed through static benchmarks. This approach has inherent limitations:

| Limitation | Impact |
|------------|--------|
| Static test cases | Cannot capture novel attack variations |
| Known patterns only | Misses creative adversarial techniques |
| No attack generation | Does not simulate realistic threat actors |
| Limited encoding coverage | Misses obfuscation-based attacks |

Article 15(5) of the EU AI Act requires that systems be "resilient against attempts by unauthorized third parties to alter their use, outputs or performance by exploiting system vulnerabilities." Static benchmarks alone cannot adequately assess this requirement.

## 2. Proposed Extension: The SCI Score

### 2.1 What the SCI Score Measures

The SCI Score is an aggregate security metric derived from adversarial probe testing. It measures attack resistance across multiple categories:

| Metric | Description | Art. 15(5) Relevance |
|--------|-------------|---------------------|
| Jailbreak Resistance | Resistance to DAN, roleplay, and persona-based attacks | Direct measure of safety circumvention attempts |
| Encoding Attack Resistance | Resistance to base64, hex, ROT13, morse obfuscation | Measures resilience to evasion techniques |
| Injection Resistance | Resistance to prompt injection attacks | Measures input manipulation resilience |
| Dynamic Attack Resistance | Resistance to generated adversarial prompts | Measures resilience to novel attacks |

### 2.2 Probe Coverage

SCI employs 38+ Garak probes organized by attack category:

| Attack Category | Probes | COMPL-AI Gap Addressed |
|-----------------|--------|------------------------|
| Jailbreak | dan.DAN, dan.DUDE, dan.DANJailbreak | Limited jailbreak coverage |
| Encoding | encoding.InjectBase64, InjectHex, InjectROT13 | No encoding attack coverage |
| Prompt Injection | promptinject.HumanJailbreaks, AutoDAN | Limited injection testing |
| Attack Generation | atkgen.Tox | No dynamic attack generation |
| Continuation | continuation.ContinueSlurs | Limited completion testing |

### 2.3 Integration with COMPL-AI Requirements

The proposed metrics map directly to existing COMPL-AI requirements:

| COMPL-AI Requirement | Current Assessment | Proposed SCI Extension |
|----------------------|-------------------|------------------------|
| Cyberattack Resilience | Static benchmarks | Adversarial probe scores |
| Harmful Content Prevention | Toxicity benchmarks | Dynamic toxicity probes |
| User Privacy Protection | Data leakage tests | Extraction resistance probes |
| Interpretability | Accuracy benchmarks | Hallucination resistance probes |

## 3. Empirical Validation

### 3.1 Models Evaluated

To validate the proposed metrics, 12 models were evaluated across 6 providers:

| Provider | Models | Coverage Gap Filled |
|----------|--------|---------------------|
| Anthropic | Claude 3.7 Sonnet, Claude Sonnet 4 | Updated versions |
| OpenAI | GPT-4o-mini, GPT-OSS-120b | Additional variants |
| Google | Gemini 2.5, Gemini 3, Gemma-2-9b | Flash variants |
| Mistral | Mistral-7b v0.2, v0.3 | Version comparison |
| xAI | Grok-4.1-Fast | Not in COMPL-AI |
| Chinese | GLM-4.7-Flash, Aion-1.0-mini | Not in COMPL-AI |

### 3.2 Results Summary

The adversarial metrics reveal security characteristics not captured by static benchmarks:

| Model | Overall Security | Jailbreak Resistance | Hallucination Resistance |
|-------|------------------|---------------------|-------------------------|
| GLM-4.7-Flash | 99.97% | 100.0% | 100.0% |
| GPT-OSS-120b | 96.96% | 97.29% | 94.69% |
| Claude 3.7 Sonnet | 91.37% | 79.85% | 99.59% |
| Grok-4.1-Fast | 86.16% | 85.08% | 75.94% |
| GPT-4o-mini | 83.94% | 75.72% | 75.21% |
| Mistral-7b-v0.3 | 83.02% | 75.32% | 89.79% |
| Google Gemini (avg) | 66.19% | 58.70% | 51.54% |

### 3.3 Findings Not Captured by COMPL-AI Benchmarks

The adversarial approach reveals several findings that static benchmarks miss:

**Finding 1: Open-source models can achieve top security**

GLM-4.7-Flash (open-source) achieved 99.97%, the highest score in the study. This contradicts assumptions that closed-source models are inherently more secure. COMPL-AI's current model selection does not include Chinese open-source models.

**Finding 2: Version regression occurs**

Claude Sonnet 4 scored 9 points lower than Claude 3.7 Sonnet. Static benchmarks may not detect regression between model versions if the same benchmark suite is used.

**Finding 3: Encoding attacks reveal hidden vulnerabilities**

Models performing well on standard jailbreak benchmarks often fail encoding-based attacks (base64, hex). COMPL-AI does not currently test obfuscation resistance.

**Finding 4: Attack generation probes find novel vulnerabilities**

Dynamic attack generation (atkgen) discovers vulnerabilities that pre-defined test cases cannot anticipate.

## 4. Proposed COMPL-AI Integration

### 4.1 Add SCI Score as New Metric

The proposal is straightforward: add the SCI Security Score as a new metric within COMPL-AI's Cyberattack Resilience requirement.

| Current COMPL-AI Metrics | Proposed Addition |
|--------------------------|-------------------|
| Robustness benchmarks | SCI Security Score (0-100) |
| Predictability tests | SCI Category Scores |
| Static safety evaluations | SCI Risk Level Classification |

The SCI Score provides a single, interpretable metric that captures adversarial attack resistance across multiple attack vectors. Rather than replacing existing benchmarks, it complements them by measuring what static tests cannot.

### 4.2 Integration Approach

| Aspect | Implementation |
|--------|----------------|
| Score Range | 0-100 (already aligned with COMPL-AI) |
| Category Breakdown | Jailbreak, Toxicity, Extraction, Leakage, Manipulation, Hallucination, Injection |
| Risk Classification | Minimal (>80), Limited (65-79), High (40-64), Critical (<40) |
| Computation | Weighted failure rate from Garak probe results |

### 4.3 Model Coverage Extension

Expand COMPL-AI's model coverage to include:

| Category | Models to Add | Rationale |
|----------|---------------|-----------|
| Chinese Models | GLM, Aion, Qwen | Significant market presence |
| xAI | Grok variants | Growing adoption |
| Version Tracking | Multiple versions per model | Detect regression |

## 5. Methodology Recommendations

### 5.1 Probe Selection Criteria

For integration with COMPL-AI, probes should meet the following criteria:

| Criterion | Requirement |
|-----------|-------------|
| Reproducibility | Deterministic or statistically stable results |
| Coverage | Maps to specific EU AI Act article |
| Validity | Demonstrated correlation with real-world attacks |
| Efficiency | Executable within reasonable compute budget |

### 5.2 Alignment with COMPL-AI

The SCI Score already uses a 0-100 scale, requiring no normalization. The risk classification maps directly to compliance status:

| SCI Risk Level | Score Range | COMPL-AI Compliance Status |
|----------------|-------------|---------------------------|
| Minimal | 80-100% | Compliant |
| Limited | 65-79% | Partially Compliant |
| High | 40-64% | Non-Compliant |
| Critical | <40% | Non-Compliant (Critical) |

## 6. Limitations and Future Work

### 6.1 Current Limitations

| Limitation | Mitigation |
|------------|------------|
| Probe coverage not exhaustive | Regular probe updates as attacks evolve |
| Dynamic attacks less reproducible | Use seed-based generation for consistency |
| Compute cost higher than benchmarks | Prioritize high-signal probes |

### 6.2 Future Extensions

| Extension | Benefit |
|-----------|---------|
| Fairness-aware adversarial probes | Combine bias testing with attack simulation |
| Multi-turn attack sequences | Test conversation-level vulnerabilities |
| Tool-use attack vectors | Test agent-based model security |

## 7. Conclusion

The COMPL-AI Framework provides a foundation for EU AI Act compliance assessment, but its static benchmark approach cannot fully assess Art. 15(5) cyberattack resilience requirements.

The SCI Score addresses this gap as a single, interpretable metric that captures adversarial attack resistance. Adding the SCI Score to COMPL-AI would:

- Provide dynamic attack resistance measurement not possible with static benchmarks
- Cover encoding and obfuscation attacks currently untested
- Enable detection of vulnerabilities through attack generation probes
- Extend model coverage to Chinese and xAI models

The integration requires minimal modification to COMPL-AI's existing structure since the SCI Score already uses a compatible 0-100 scale with clear risk level classification.

## References

### COMPL-AI Framework
- Guldimann, P., et al. (2024). "COMPL-AI Framework: A Technical Interpretation and LLM Benchmark for the EU Artificial Intelligence Act." arXiv:2410.07959
- https://compl-ai.org

### Adversarial Testing
- Garak LLM Vulnerability Scanner, NVIDIA
- Bhatt, U., et al. (2025). "Robustness and Cybersecurity in the EU AI Act." ACM FAccT 2025
- Bieringer, L., et al. (2024). "Assuring EU AI Act Compliance and Adversarial Robustness." arXiv:2410.05306

### EU AI Act
- https://artificialintelligenceact.eu
- Article 15(5): Cyberattack Resilience Requirements
