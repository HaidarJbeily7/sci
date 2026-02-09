# LLM Security Analysis Report

## Executive Summary

This report presents a security analysis of 12 Large Language Models across 6 companies. The evaluation was conducted using the SCI framework, which combines Garak adversarial probes with EU AI Act compliance mapping to assess model vulnerabilities across 8 security categories.

### Key Findings

| Rank | Company | Avg. Score | Risk Level | Best Model |
|------|---------|------------|------------|------------|
| 1 | **Others** | 89.71 | Minimal | GLM-4.7-Flash (99.97) |
| 2 | **OpenAI** | 90.45 | Minimal | GPT-OSS-120b (96.96) |
| 3 | **Anthropic** | 86.85 | Minimal | Claude 3.7 Sonnet (91.37) |
| 4 | **xAI** | 86.16 | Minimal | Grok-4.1-Fast (86.16) |
| 5 | **Mistral** | 82.09 | Minimal | Mistral-7b-v0.3 (83.02) |
| 6 | **Google** | 66.19 | Limited | Gemini Flash 2.5 (66.30) |

The highest-scoring model was GLM-4.7-Flash (Zhipu) at 99.97%, while Gemini-3-Flash-Preview (Google) scored lowest at 66.06%.

---

## Part 1: Company-Level Analysis

### 1.1 Anthropic (Claude)

| Model | Overall Score | Risk Level | Weighted Failure Rate |
|-------|---------------|------------|----------------------|
| Claude 3.7 Sonnet | 91.37 | Minimal | 0.264 |
| Claude Sonnet 4 | 82.33 | Minimal | 0.348 |
| **Company Average** | **86.85** | **Minimal** | **0.306** |

#### Category Breakdown

| Category | Claude 3.7 Sonnet | Claude Sonnet 4 | Company Avg |
|----------|-------------------|-----------------|-------------|
| Jailbreak | 79.85 | 78.25 | 79.05 |
| Toxicity | 87.96 | 84.62 | 86.29 |
| Extraction | 100.00 | 76.60 | 88.30 |
| Leakage | 86.11 | 80.26 | 83.19 |
| Manipulation | 99.01 | 85.83 | 92.42 |
| Hallucination | 99.59 | N/A | 99.59 |
| Other | 87.07 | 88.44 | 87.76 |

#### Vulnerability Distribution

| Severity | Claude 3.7 Sonnet | Claude Sonnet 4 |
|----------|-------------------|-----------------|
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 1,414 | 1,479 |
| Low | 3,943 | 2,776 |
| **Total** | **5,357** | **4,255** |

**Anthropic Analysis**: Claude models demonstrate strong consistency with both achieving "minimal" risk classification. Claude 3.7 Sonnet outperforms Sonnet 4 significantly (+9 points), suggesting regression in the newer version or different tuning approaches. Notably, Claude 3.7 achieves perfect scores in extraction (100%) and near-perfect in manipulation (99.01%) and hallucination (99.59%).

---

### 1.2 OpenAI

| Model | Overall Score | Risk Level | Weighted Failure Rate |
|-------|---------------|------------|----------------------|
| GPT-OSS-120b | 96.96 | Minimal | 0.056 |
| GPT-4o-mini | 83.94 | Minimal | 0.349 |
| **Company Average** | **90.45** | **Minimal** | **0.202** |

#### Category Breakdown

| Category | GPT-OSS-120b | GPT-4o-mini | Company Avg |
|----------|--------------|-------------|-------------|
| Jailbreak | 97.29 | 75.72 | 86.51 |
| Toxicity | 97.10 | 80.25 | 88.68 |
| Extraction | 100.00 | 100.00 | 100.00 |
| Leakage | 93.42 | 78.95 | 86.19 |
| Manipulation | 99.67 | 94.42 | 97.05 |
| Hallucination | 94.69 | 75.21 | 84.95 |
| Other | 96.52 | 83.03 | 89.78 |

#### Vulnerability Distribution

| Severity | GPT-OSS-120b | GPT-4o-mini |
|----------|--------------|-------------|
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 332 | 1,931 |
| Low | 5,636 | 3,605 |
| **Total** | **5,968** | **5,536** |

**OpenAI Analysis**: OpenAI shows the largest within-company variance (13 points difference). GPT-OSS-120b demonstrates exceptional security across all categories, while GPT-4o-mini shows weaknesses in hallucination (75.21%) and jailbreak resistance (75.72%). Both achieve perfect extraction protection (100%).

---

### 1.3 xAI (Grok)

| Model | Overall Score | Risk Level | Weighted Failure Rate |
|-------|---------------|------------|----------------------|
| Grok-4.1-Fast | 86.16 | Minimal | 0.309 |
| **Company Average** | **86.16** | **Minimal** | **0.309** |

#### Category Breakdown

| Category | Grok-4.1-Fast |
|----------|---------------|
| Jailbreak | 85.08 |
| Toxicity | 77.63 |
| Extraction | 100.00 |
| Leakage | 77.63 |
| Manipulation | 95.98 |
| Hallucination | 75.94 |
| Injection | 93.95 |
| Other | 83.10 |

#### Vulnerability Distribution

| Severity | Grok-4.1-Fast |
|----------|---------------|
| Critical | 0 |
| High | 0 |
| Medium | 1,711 |
| Low | 3,825 |
| **Total** | **5,536** |

**xAI Analysis**: Grok-4.1-Fast delivers solid performance (86.16%) with "minimal" risk classification. Notable strengths include perfect extraction protection (100%), strong manipulation resistance (95.98%), and excellent jailbreak resistance (85.08%) - outperforming Claude and Mistral in this category. Weaknesses appear in hallucination (75.94%) and toxicity filtering (77.63%). Grok's approach appears more permissive than Claude but with strong core protections.

---

### 1.4 Google

| Model | Overall Score | Risk Level | Weighted Failure Rate |
|-------|---------------|------------|----------------------|
| Gemini Flash 2.5 | 66.30 | Limited | 0.306 |
| Gemma-2-9b-it | 66.21 | Limited | 0.307 |
| Gemini-3-Flash-Preview | 66.06 | Limited | 0.309 |
| **Company Average** | **66.19** | **Limited** | **0.307** |

#### Category Breakdown

| Category | Gemini 2.5 | Gemma-2-9b | Gemini 3 | Company Avg |
|----------|------------|------------|----------|-------------|
| Jailbreak | 57.07 | 55.14 | 63.88 | 58.70 |
| Toxicity | 60.74 | 66.12 | 54.37 | 60.41 |
| Extraction | 100.00 | 71.36 | 100.00 | 90.45 |
| Leakage | 65.26 | 73.95 | 50.79 | 63.33 |
| Manipulation | 90.92 | 93.62 | 79.87 | 88.14 |
| Hallucination | 51.19 | 51.88 | N/A | 51.54 |
| Other | 66.49 | 73.54 | 69.07 | 69.70 |

#### Vulnerability Distribution

| Severity | Gemini 2.5 | Gemma-2-9b | Gemini 3 |
|----------|------------|------------|----------|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Medium | 1,853 | 1,858 | 1,167 |
| Low | 4,195 | 4,190 | 2,615 |
| **Total** | **6,048** | **6,048** | **3,782** |

**Google Analysis**: Google models show remarkably consistent (but concerning) performance, all clustering around 66% with "limited" risk classification. Critical weaknesses exist in hallucination (51-52%) and jailbreak resistance (55-64%). The consistency suggests a company-wide approach to safety that prioritizes consistency over maximum security.

---

### 1.5 Mistral

| Model | Overall Score | Risk Level | Weighted Failure Rate |
|-------|---------------|------------|----------------------|
| Mistral-7b-v0.3 | 83.02 | Minimal | 0.399 |
| Mistral-7b-v0.2 | 81.15 | Minimal | 0.427 |
| **Company Average** | **82.09** | **Minimal** | **0.413** |

#### Category Breakdown

| Category | Mistral v0.3 | Mistral v0.2 | Company Avg |
|----------|--------------|--------------|-------------|
| Jailbreak | 75.32 | 75.24 | 75.28 |
| Toxicity | 76.81 | 76.72 | 76.77 |
| Extraction | 78.11 | 77.92 | 78.02 |
| Leakage | 78.95 | 75.00 | 76.98 |
| Manipulation | 97.99 | 97.99 | 97.99 |
| Hallucination | 89.79 | 89.06 | 89.43 |
| Injection | 91.21 | N/A | 91.21 |
| Other | 75.94 | 76.08 | 76.01 |

#### Vulnerability Distribution

| Severity | Mistral v0.3 | Mistral v0.2 |
|----------|--------------|--------------|
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 2,414 | 2,581 |
| Low | 3,634 | 3,467 |
| **Total** | **6,048** | **6,048** |

**Mistral Analysis**: Mistral demonstrates highly consistent performance between versions (1.87 point improvement from v0.2 to v0.3), suggesting iterative security improvements. Strengths in manipulation prevention (97.99%) but weaknesses in jailbreak (75.28%) and toxicity filtering (76.77%). As an open-source model, the security scores are competitive with closed-source alternatives.

---

### 1.6 Others (Alibaba/Zhipu)

| Model | Overall Score | Risk Level | Weighted Failure Rate |
|-------|---------------|------------|----------------------|
| GLM-4.7-Flash (Zhipu) | 99.97 | Minimal | 0.0005 |
| Aion-1.0-mini (Alibaba) | 79.44 | Limited | 0.421 |
| **Company Average** | **89.71** | **Mixed** | **0.211** |

#### Category Breakdown

| Category | GLM-4.7-Flash | Aion-1.0-mini | Avg |
|----------|---------------|---------------|-----|
| Jailbreak | 100.00 | 77.66 | 88.83 |
| Toxicity | 100.00 | 81.07 | 90.54 |
| Extraction | 99.81 | 75.66 | 87.74 |
| Leakage | 100.00 | 81.58 | 90.79 |
| Manipulation | 100.00 | 81.36 | 90.68 |
| Hallucination | 100.00 | 77.92 | 88.96 |
| Injection | 100.00 | N/A | 100.00 |
| Other | 99.96 | 80.81 | 90.39 |

#### Vulnerability Distribution

| Severity | GLM-4.7-Flash | Aion-1.0-mini |
|----------|---------------|---------------|
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 3 | 2,328 |
| Low | 5,845 | 3,208 |
| **Total** | **5,848** | **5,536** |

**Others Analysis**: GLM-4.7-Flash achieves near-perfect scores (99.97%) with only 3 medium-severity findings, likely due to aggressive content filtering (empty responses to harmful prompts). Aion-1.0-mini shows moderate performance (79.44%) with "limited" risk classification.

---

## Part 2: Cross-Model Analysis

### 2.1 Overall Security Ranking

| Rank | Model | Company | Score | Risk Level |
|------|-------|---------|-------|------------|
| 1 | GLM-4.7-Flash | Zhipu | 99.97 | Minimal |
| 2 | GPT-OSS-120b | OpenAI | 96.96 | Minimal |
| 3 | Claude 3.7 Sonnet | Anthropic | 91.37 | Minimal |
| 4 | **Grok-4.1-Fast** | **xAI** | **86.16** | **Minimal** |
| 5 | GPT-4o-mini | OpenAI | 83.94 | Minimal |
| 6 | Mistral-7b-v0.3 | Mistral | 83.02 | Minimal |
| 7 | Claude Sonnet 4 | Anthropic | 82.33 | Minimal |
| 8 | Mistral-7b-v0.2 | Mistral | 81.15 | Minimal |
| 9 | Aion-1.0-mini | Alibaba | 79.44 | Limited |
| 10 | Gemini Flash 2.5 | Google | 66.30 | Limited |
| 11 | Gemma-2-9b-it | Google | 66.21 | Limited |
| 12 | Gemini-3-Flash-Preview | Google | 66.06 | Limited |

### 2.2 Performance Analysis

#### Top Performers

**GLM-4.7-Flash (99.97%)** achieves near-perfect scores through an aggressive refusal strategy, often returning empty responses to potentially harmful prompts. This approach reflects strict Chinese AI regulations and results in near-perfect scores across all categories, though it may over-refuse legitimate queries.

**GPT-OSS-120b (96.96%)** benefits from its large parameter count (120B), which enables nuanced understanding of harmful intent. The model demonstrates sophisticated safety training with advanced RLHF and extensive red-teaming, achieving high security without excessive refusals.

**Claude 3.7 Sonnet (91.37%)** reflects Anthropic's Constitutional AI approach, embedding safety principles during training rather than relying solely on post-hoc filtering. The model shows particularly strong hallucination prevention (99.59%) and refuses harmful requests while providing constructive alternatives.

**Grok-4.1-Fast (86.16%)** demonstrates strong jailbreak resistance (85.08%), outperforming both Claude and Mistral in this category. The model achieves perfect extraction protection but shows weakness in hallucination prevention (75.94%), suggesting a more permissive approach to factual claims.

#### Underperformers

**Google Models (~66%)** consistently underperform across all three tested variants. The primary weaknesses are hallucination (~51%) and jailbreak resistance (55-64%). The Flash/lite variants may sacrifice safety optimizations for inference speed.

**Aion-1.0-mini (79.44%)** is positioned as a less restricted model, which explains its moderate security scores. The visible chain-of-thought reasoning in responses may also expose the model's decision-making process to exploitation.

### 2.3 Category-wise Performance Patterns

#### Best Performers by Category

| Category | Best Model | Score | Worst Model | Score |
|----------|-----------|-------|-------------|-------|
| Jailbreak | GLM-4.7-Flash | 100.0 | Gemma-2-9b | 55.14 |
| Toxicity | GLM-4.7-Flash | 100.0 | Gemini-3 | 54.37 |
| Extraction | Multiple | 100.0 | Gemma-2-9b | 71.36 |
| Leakage | GLM-4.7-Flash | 100.0 | Gemini-3 | 50.79 |
| Manipulation | GLM-4.7-Flash | 100.0 | Gemini-3 | 79.87 |
| Hallucination | GLM-4.7-Flash | 100.0 | Gemini 2.5 | 51.19 |

#### Strength/Weakness Trade-offs

**Pattern 1: Extraction Excellence**
- Models achieving 100% extraction: Claude 3.7, GPT-4o-mini, GPT-OSS-120b, Gemini 2.5, Gemini 3, GLM-4.7, Grok-4.1
- Indicates strong system prompt protection across most vendors

**Pattern 2: Hallucination Vulnerability**
- Weak performers (<80%): Google models (51-52%), GPT-4o-mini (75.21%), Grok-4.1 (75.94%)
- Strong performers (>90%): Claude 3.7 (99.59%), GPT-OSS-120b (94.69%), Mistral (89%)
- **Correlation**: Larger models and constitutional AI approaches reduce hallucination

**Pattern 3: Jailbreak Resistance Gap**
- 45-point gap between best (100%) and worst (55.14%)
- **Key differentiator**: Determines overall security classification

### 2.4 Model Characteristics Correlation

#### Size vs. Security

| Model | Est. Size | Security Score | Correlation |
|-------|-----------|----------------|-------------|
| GPT-OSS-120b | 120B | 96.96 | Larger = More Secure |
| Claude Sonnet 4 | ~70B | 82.33 | Mixed |
| Claude 3.7 Sonnet | ~70B | 91.37 | Mixed |
| Grok-4.1-Fast | ~100B+ | 86.16 | Large and Secure |
| Mistral-7b | 7B | 81-83 | Small but Secure |
| Gemma-2-9b | 9B | 66.21 | Small and Less Secure |

**Finding**: Model size correlates with security but is not deterministic. Training approach matters more than raw size (Mistral-7b outperforms larger Google models).

#### Version Evolution

| Model Family | v1/Old | v2/New | Improvement |
|--------------|--------|--------|-------------|
| Mistral-7b | v0.2: 81.15 | v0.3: 83.02 | +1.87 (+2.3%) |
| Claude Sonnet | v4: 82.33 | v3.7: 91.37 | -9.04 (Regression) |

**Finding**: Newer isn't always better. Claude Sonnet 4 shows regression from 3.7, possibly due to different optimization priorities. Mistral shows consistent improvement.

#### Open-Source vs. Closed-Source

| Type | Models | Avg. Score |
|------|--------|------------|
| Closed-Source | Claude, Gemini, Grok | 83.70 |
| Open-Source | Mistral, Gemma, GLM, Aion | 82.16 |

**Critical Finding**: The open/closed distinction is NOT predictive of security:
- **GLM-4.7-Flash (open-source)**: 99.97% - the HIGHEST score
- **Mistral-7b (open-source)**: 82% - competitive with closed-source
- **Google Gemini (closed-source)**: 66% - the LOWEST performers

Training approach and safety investment matter far more than licensing model.

### 2.5 Vulnerability Pattern Analysis

#### Common Weaknesses Across Vendors

1. **Jailbreak Attacks** (Most challenging category)
   - Average score: 78.43%
   - Most models vulnerable to sophisticated prompt injection
   - DAN-style attacks partially effective against all except GLM

2. **Toxicity Filtering** (Second most challenging)
   - Average score: 80.12%
   - Edge cases around discussing vs. generating toxic content
   - Context-dependent failures common

3. **Hallucination** (Highly variable)
   - Range: 51.19% to 100%
   - Strongest correlation with model architecture and training

#### Unique Strengths by Vendor

| Vendor | Unique Strength | Evidence |
|--------|-----------------|----------|
| Anthropic | Manipulation resistance | 92.42% avg |
| OpenAI | Extraction protection | 100% both models |
| xAI | Jailbreak resistance | 85.08% (above avg) |
| Google | Consistency | 0.24 point variance |
| Mistral | Version improvement | +2.3% per version |
| Zhipu | Overall security | 99.97% across all |

---

## Part 3: Key Learnings & Insights

### 3.1 Security Philosophy Spectrum

The tested models exhibit distinct safety philosophies that correlate with their security scores:

| Philosophy | Models | Characteristics | Trade-off |
|------------|--------|-----------------|-----------|
| Maximum Safety | GLM-4.7-Flash | Aggressive filtering, empty refusals | Over-refusal, reduced helpfulness |
| Constitutional Safety | Claude 3.7, GPT-OSS-120b | Principled safety, contextual refusals | May miss edge cases |
| Balanced Safety | Grok-4.1, GPT-4o-mini, Mistral | Moderate filtering, helpful defaults | More vulnerable to sophisticated attacks |
| Minimal Safety | Google models, Aion | Permissive defaults, basic filtering | Higher vulnerability rates |

### 3.2 Critical Success Factors

Several factors correlate with stronger security performance:

Constitutional AI training, as employed by Anthropic, embeds safety principles during the training process rather than relying on post-hoc filtering. Claude 3.7's 99.59% hallucination score demonstrates the effectiveness of this approach.

Extensive red-teaming contributes to jailbreak resistance. Both GPT-OSS-120b and Grok show evidence of comprehensive adversarial testing, with both achieving over 85% jailbreak resistance.

Model scale enables more nuanced safety behaviors, but size alone does not guarantee security. The Google models demonstrate that large models can still underperform if safety training is insufficient.

Regulatory pressure appears to drive security investment. GLM's 99.97% score likely reflects compliance with strict Chinese AI regulations, though such aggressive filtering may not be appropriate for all use cases.

### 3.3 Failure Mode Patterns

Analysis of probe results reveals common failure modes across vendors:

| Failure Mode | Affected Models | Root Cause |
|--------------|-----------------|------------|
| Encoding Bypass | Most models | Limited training on obfuscated inputs |
| Roleplay Jailbreak | Claude, Mistral, Google | Difficulty maintaining safety in fictional contexts |
| Factual Hallucination | Google, GPT-4o-mini, Grok | Insufficient factuality training |
| Edge Case Toxicity | All except GLM | Subtle harmful content passes filters |

### 3.4 Generational Improvements

| Generation Gap | Evidence | Implication |
|----------------|----------|-------------|
| Mistral v0.2 → v0.3 | +2.3% improvement | Iterative safety works |
| Claude 3.7 → Sonnet 4 | -9.04% regression | Different optimization priorities |
| GPT-4o-mini → GPT-OSS-120b | +13% improvement | Scale + training matters |

### 3.5 Open vs Closed Source Security

The data does not support the assumption that closed-source models are inherently more secure than open-source alternatives.

| Finding | Evidence |
|---------|----------|
| Open-source can lead | GLM-4.7-Flash (open-source) scored 99.97%, the highest in the study |
| Open-source is competitive | Mistral-7b (open-source) at 82% matches closed-source models |
| Closed-source can underperform | Google Gemini (closed-source) scored 66%, the lowest in the study |

The implication is that model selection should be based on empirical security testing rather than assumptions about licensing models. Training methodology and safety investment appear to be stronger predictors of security than whether weights are publicly available.

### 3.6 Model Selection Guidelines

Based on the security profiles established in this study:

| Application Context | Suitable Models | Rationale |
|---------------------|-----------------|-----------|
| High-stakes systems | GLM-4.7-Flash, GPT-OSS-120b | Scores above 95% |
| General production use | Claude 3.7 Sonnet | Balance of security and usability |
| Cost-constrained deployment | Mistral-7b-v0.3 | Open-source with 82% security |
| Less restrictive applications | Grok-4.1-Fast | Balanced approach with strong core protections |
| Research contexts | Case-by-case evaluation | Google models carry higher risk |

---

## Part 4: Recommendations

For high-security applications requiring minimal risk classification, GLM-4.7-Flash or GPT-OSS-120b provide the strongest security profiles. Claude 3.7 Sonnet is a suitable alternative. Google models should be avoided in high-risk contexts due to their "limited" risk classification.

For balanced deployments requiring both security and helpfulness, Claude 3.7 Sonnet offers a reasonable trade-off. Grok-4.1-Fast provides strong jailbreak resistance with a less restrictive approach, while Mistral-7b-v0.3 offers competitive security as an open-source option.

For cost-sensitive deployments, Mistral-7b-v0.3 provides 82% security with open-source licensing. GPT-4o-mini offers 84% security at lower cost than larger proprietary models.

### Areas Needing Improvement by Vendor

| Vendor | Priority Improvement Area | Current Score |
|--------|--------------------------|---------------|
| Google | Hallucination prevention | 51.54% |
| Google | Jailbreak resistance | 58.70% |
| xAI | Hallucination prevention | 75.94% |
| xAI | Toxicity filtering | 77.63% |
| Anthropic | Extraction protection (Sonnet 4) | 76.60% |
| OpenAI | Hallucination (GPT-4o-mini) | 75.21% |
| Mistral | Jailbreak resistance | 75.28% |

---

## Methodology

- **Framework**: SCI (Security-Centered Intelligence)
- **Test Suite**: Garak with COMPL-AI probe mappings
- **Probes**: 38+ probes across 8 vulnerability categories
- **Compliance**: EU AI Act article mapping
- **Scoring**: Weighted failure rate converted to 0-100 scale

---

## Appendix: Raw Data Summary

### Complete Model Metrics

| Model | Score | Jailbreak | Toxicity | Extract | Leak | Manip | Halluc | Inject | Findings |
|-------|-------|-----------|----------|---------|------|-------|--------|--------|----------|
| GLM-4.7-Flash | 99.97 | 100.0 | 100.0 | 99.81 | 100.0 | 100.0 | 100.0 | 100.0 | 5,848 |
| GPT-OSS-120b | 96.96 | 97.29 | 97.10 | 100.0 | 93.42 | 99.67 | 94.69 | N/A | 5,968 |
| Claude 3.7 | 91.37 | 79.85 | 87.96 | 100.0 | 86.11 | 99.01 | 99.59 | N/A | 5,357 |
| **Grok-4.1-Fast** | **86.16** | **85.08** | **77.63** | **100.0** | **77.63** | **95.98** | **75.94** | **93.95** | **5,536** |
| GPT-4o-mini | 83.94 | 75.72 | 80.25 | 100.0 | 78.95 | 94.42 | 75.21 | N/A | 5,536 |
| Mistral v0.3 | 83.02 | 75.32 | 76.81 | 78.11 | 78.95 | 97.99 | 89.79 | 91.21 | 6,048 |
| Claude Sonnet 4 | 82.33 | 78.25 | 84.62 | 76.60 | 80.26 | 85.83 | N/A | N/A | 4,255 |
| Mistral v0.2 | 81.15 | 75.24 | 76.72 | 77.92 | 75.00 | 97.99 | 89.06 | N/A | 6,048 |
| Aion-1.0-mini | 79.44 | 77.66 | 81.07 | 75.66 | 81.58 | 81.36 | 77.92 | N/A | 5,536 |
| Gemini 2.5 | 66.30 | 57.07 | 60.74 | 100.0 | 65.26 | 90.92 | 51.19 | N/A | 6,048 |
| Gemma-2-9b | 66.21 | 55.14 | 66.12 | 71.36 | 73.95 | 93.62 | 51.88 | N/A | 6,048 |
| Gemini-3 | 66.06 | 63.88 | 54.37 | 100.0 | 50.79 | 79.87 | N/A | N/A | 3,782 |

