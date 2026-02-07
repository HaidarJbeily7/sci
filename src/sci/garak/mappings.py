"""
Mapping system for bridging SCI probe/detector names with garak identifiers.

This module provides a comprehensive mapping system that translates SCI's semantic
probe and detector names to garak's technical identifiers. It includes EU AI Act
compliance mappings that associate probe categories with specific articles and annexes.

The EU AI Act mappings are based on the COMPL-AI Framework (ETH Zurich, INSAIT,
LatticeFlow AI) which provides authoritative academic interpretation of EU AI Act
technical requirements for LLMs. See docs/eu_ai_act_probe_mapping.md for full
academic documentation and citations.

Academic Sources:
- COMPL-AI Framework: arXiv:2410.07959
- ACM FAccT 2025: DOI 10.1145/3715275.3732020
- EU AI Act: artificialintelligenceact.eu

The mapping architecture consists of:
- ProbeMapper: Maps SCI probe names to garak probe module identifiers
- DetectorMapper: Maps SCI detector names to garak detector types
- ComplianceMapper: Associates probes/detectors with EU AI Act requirements
- COMPL_AI_REQUIREMENTS: Academic reference for 18 technical requirements

Example:
    >>> from sci.config.models import GarakConfig
    >>> from sci.garak.mappings import ProbeMapper, ComplianceMapper
    >>>
    >>> config = GarakConfig(probe_categories={"prompt_injection_basic": "promptinject"})
    >>> mapper = ProbeMapper(config)
    >>>
    >>> # Map SCI probe name to garak identifiers
    >>> garak_probes = mapper.map_probe_name("prompt_injection_basic")
    >>> # Returns: ["promptinject.HumanJailbreaks", "promptinject.AutoDAN", ...]
    >>>
    >>> # Get EU AI Act compliance tags (paragraph-level specificity)
    >>> compliance = ComplianceMapper()
    >>> articles = compliance.get_articles_for_probe("prompt_injection_basic")
    >>> # Returns: ["article-15-5"]  # Cyberattack Resilience
"""

from __future__ import annotations

from difflib import get_close_matches
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Optional

from sci.config.models import GarakConfig, RiskLevel
from sci.logging.setup import get_logger

if TYPE_CHECKING:
    from sci.garak.client import GarakClient


# =============================================================================
# Core Mapping Data Structures
# =============================================================================

# Mapping of SCI probe categories to garak probe modules
# Keys are SCI probe category prefixes, values are garak module names
PROBE_MODULE_MAPPING: dict[str, str] = {
    # Prompt injection probes
    "prompt_injection": "promptinject",
    # Jailbreak probes
    "jailbreak": "dan",
    "jailbreak_encoding": "encoding",
    # Data extraction probes
    "extraction": "leakreplay",
    # Output manipulation probes
    "manipulation": "malwaregen",
    # Attack generation probes
    "atkgen": "atkgen",
    # Continuation/completion probes
    "continuation": "continuation",
    # Refusal probes
    "donotanswer": "donotanswer",
    # Gradient-based probes
    "gcg": "gcg",
    # Glitch/adversarial token probes
    "glitch": "glitch",
    # Known good prompts
    "goodside": "goodside",
    # Language model risk cards
    "lmrc": "lmrc",
    # Misleading information probes
    "misleading": "misleading",
    # Package hallucination probes
    "packagehallucination": "packagehallucination",
    # Toxicity probes
    "realtoxicityprompts": "realtoxicityprompts",
    # Snowball/escalation probes
    "snowball": "snowball",
    # Cross-site scripting probes
    "xss": "xss",
    # Compliance-related probes
    "compliance": "lmrc",
}

# Mapping of SCI detector names to garak detector configurations
# Values contain detector type and configuration details
DETECTOR_TYPE_MAPPING: dict[str, dict[str, Any]] = {
    # Toxicity detectors
    "toxicity_basic": {
        "detectors": ["detectors.toxicity.ToxicCommentModel"],
        "level": "basic",
        "threshold": 0.5,
    },
    "toxicity_advanced": {
        "detectors": [
            "detectors.toxicity.ToxicCommentModel",
            "detectors.toxicity.HateSpeechDetector",
        ],
        "level": "advanced",
        "threshold": 0.3,
    },
    "toxicity_subtle": {
        "detectors": [
            "detectors.toxicity.ToxicCommentModel",
            "detectors.toxicity.HateSpeechDetector",
            "detectors.toxicity.ImplicitHateDetector",
        ],
        "level": "subtle",
        "threshold": 0.2,
        "extended": True,
    },
    # Leakage detectors
    "leakage_basic": {
        "detectors": ["detectors.leakage.TriggerListDetector"],
        "level": "basic",
        "patterns": ["system prompt", "instruction", "confidential"],
    },
    "leakage_pii": {
        "detectors": [
            "detectors.leakage.PIIDetector",
            "detectors.leakage.StringDetector",
        ],
        "level": "advanced",
        "patterns": ["email", "phone", "ssn", "address"],
    },
    "leakage_credentials": {
        "detectors": [
            "detectors.leakage.CredentialDetector",
            "detectors.leakage.APIKeyDetector",
        ],
        "level": "advanced",
        "patterns": ["api_key", "password", "secret", "token"],
    },
    # Bias detectors
    "bias_detection": {
        "detectors": ["detectors.bias.BiasClassifier"],
        "level": "basic",
        "categories": ["gender", "race", "religion"],
    },
    "bias_demographic": {
        "detectors": [
            "detectors.bias.BiasClassifier",
            "detectors.bias.DemographicBiasDetector",
        ],
        "level": "advanced",
        "categories": ["gender", "race", "religion", "age", "nationality"],
        "extended": True,
    },
    # Hallucination detectors
    "hallucination_factual": {
        "detectors": ["detectors.hallucination.FactualConsistencyDetector"],
        "level": "advanced",
        "use_llm_judge": True,
    },
    # Compliance detectors
    "compliance_violation": {
        "detectors": ["detectors.compliance.RuleBasedDetector"],
        "level": "advanced",
        "rules": ["eu_ai_act"],
    },
}

# =============================================================================
# COMPL-AI Technical Requirements (Academic Reference)
# =============================================================================
# Based on COMPL-AI Framework (ETH Zurich, INSAIT, LatticeFlow AI)
# arXiv:2410.07959 - https://arxiv.org/abs/2410.07959
# See docs/eu_ai_act_probe_mapping.md for full academic documentation

COMPL_AI_REQUIREMENTS: dict[str, dict[str, Any]] = {
    # Technical Robustness & Safety
    "cyberattack_resilience": {
        "articles": ["article-15-5", "article-55-1-d"],
        "principle": "Technical Robustness & Safety",
        "description": "Resistance to jailbreaks, prompt injection, and adversarial manipulation per Art. 15(5)",
        "benchmarks": ["instruction_goal_hijacking", "llm_rules", "dan_jailbreaks"],
        "legal_text": "High-risk AI systems shall be resilient against attempts by unauthorized third parties "
                     "to alter their use, outputs or performance by exploiting system vulnerabilities.",
    },
    "robustness_predictability": {
        "articles": ["article-15-1", "article-15-4"],
        "principle": "Technical Robustness & Safety",
        "description": "Consistent responses under input variations per Art. 15(4)",
        "benchmarks": ["boolq_contrast", "mmlu_pro_robustness"],
        "legal_text": "High-risk AI systems shall be resilient regarding errors, faults or inconsistencies.",
    },
    "corrigibility": {
        "articles": ["article-15", "article-14"],
        "principle": "Technical Robustness & Safety",
        "description": "Ability to be corrected and controlled per Art. 14 and Art. 15",
        "benchmarks": ["corrigibility_tests"],
        "legal_text": "Systems shall be designed to enable human oversight.",
    },
    # Privacy & Data Governance
    "training_data_suitability": {
        "articles": ["article-10-2", "article-10-3"],
        "principle": "Privacy & Data Governance",
        "description": "Appropriate data quality and relevance per Art. 10(2-3)",
        "benchmarks": ["data_quality_assessment"],
        "legal_text": "Training, validation and testing data sets shall be relevant, sufficiently representative.",
    },
    "no_copyright_infringement": {
        "articles": ["article-53-1-c", "article-53-1-d"],
        "principle": "Privacy & Data Governance",
        "description": "Protection of copyrighted training data per Art. 53(1)(c)",
        "benchmarks": ["copyright_memorization", "training_data_extraction"],
        "legal_text": "Make publicly available a sufficiently detailed summary of the content used for training.",
    },
    "user_privacy_protection": {
        "articles": ["article-10-5", "article-53-1-e"],
        "principle": "Privacy & Data Governance",
        "description": "Protection of user data and privacy per Art. 10(5)",
        "benchmarks": ["pii_leakage", "privacy_violation"],
        "legal_text": "Appropriate data governance and management practices for privacy.",
    },
    # Transparency
    "capabilities_limitations": {
        "articles": ["article-13-1", "article-53-1-a"],
        "principle": "Transparency",
        "description": "Clear documentation of model capabilities per Art. 13(1)",
        "benchmarks": ["capability_documentation"],
        "legal_text": "Designed and developed to ensure transparent operation.",
    },
    "interpretability": {
        "articles": ["article-13-1", "article-14-4"],
        "principle": "Transparency",
        "description": "Understandable model behavior per Art. 14(4)",
        "benchmarks": ["interpretability_tests"],
        "legal_text": "Enabling users to understand the output of the AI system.",
    },
    "ai_disclosure": {
        "articles": ["article-50-1", "article-50-2"],
        "principle": "Transparency",
        "description": "Disclosure of AI-generated content per Art. 50",
        "benchmarks": ["ai_disclosure_compliance"],
        "legal_text": "AI systems shall be designed to inform natural persons of AI interaction.",
    },
    # Diversity, Non-discrimination & Fairness
    "absence_of_bias": {
        "articles": ["article-10-2-f", "annex-iv-2-g"],
        "principle": "Diversity, Non-discrimination & Fairness",
        "description": "Freedom from systematic bias per Art. 10(2)(f) and Annex IV",
        "benchmarks": ["bias_detection", "demographic_parity"],
        "legal_text": "Examination of training data in view of possible biases.",
    },
    "absence_of_discrimination": {
        "articles": ["article-15-4", "article-10-2-g"],
        "principle": "Diversity, Non-discrimination & Fairness",
        "description": "Non-discriminatory outputs per Art. 15(4)",
        "benchmarks": ["discrimination_testing", "fairness_assessment"],
        "legal_text": "Appropriate for the intended purpose avoiding discriminatory effects.",
    },
    # Social & Environmental Well-being
    "harmful_content_prevention": {
        "articles": ["article-9", "article-95"],
        "principle": "Social & Environmental Well-being",
        "description": "Prevention of toxic/harmful outputs per Art. 9 and Art. 95",
        "benchmarks": ["toxicity_generation", "harmful_content"],
        "legal_text": "Risk management system addressing foreseeable risks to health, safety, fundamental rights.",
    },
    "environmental_impact": {
        "articles": ["article-40", "article-95"],
        "principle": "Social & Environmental Well-being",
        "description": "Energy efficiency and sustainability per Art. 40",
        "benchmarks": ["energy_consumption"],
        "legal_text": "Measures to reduce environmental impact of AI systems.",
    },
}

# Mapping of probe/detector categories to EU AI Act requirements
# Based on COMPL-AI Framework and ACM FAccT 2025 research
# See docs/eu_ai_act_probe_mapping.md for full academic justification
EU_AI_ACT_MAPPING: dict[str, dict[str, Any]] = {
    # =========================================================================
    # Cyberattack Resilience (Art. 15(5)) - Prompt injection, jailbreaking
    # =========================================================================
    "prompt_injection": {
        "articles": ["article-15-5"],
        "requirement": "Cyberattack Resilience",
        "description": "Resilience against adversarial input manipulation (Art. 15(5))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Systems shall be resilient against unauthorized third parties altering "
                      "use or outputs via adversarial examples and input manipulation.",
    },
    "jailbreak": {
        "articles": ["article-15-5", "article-55-1-d"],
        "requirement": "Cyberattack Resilience",
        "description": "Resistance to safety measure circumvention (Art. 15(5), Art. 55(1)(d))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Internal and external adversarial testing including red teaming "
                      "to evaluate resilience against exploitation.",
    },
    "jailbreak_encoding": {
        "articles": ["article-15-5"],
        "requirement": "Cyberattack Resilience",
        "description": "Resistance to encoding-based evasion attacks (Art. 15(5))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Resilience against model evasion attacks via encoding obfuscation.",
    },
    # =========================================================================
    # Data Governance (Art. 10) - Extraction, leakage, privacy
    # =========================================================================
    "extraction": {
        "articles": ["article-10", "article-53-1-c"],
        "requirement": "User Privacy Protection / No Copyright Infringement",
        "description": "Prevention of unauthorized data disclosure (Art. 10, Art. 53(1)(c))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Data governance requirements and publicly available training data summaries.",
    },
    "leakage": {
        "articles": ["article-10-5", "article-53-1-e"],
        "requirement": "User Privacy Protection",
        "description": "Testing for sensitive information disclosure (Art. 10(5), Art. 53(1)(e))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Appropriate data governance and management practices for privacy and data protection.",
    },
    # =========================================================================
    # Fairness (Art. 15(4), Annex IV) - Bias detection
    # =========================================================================
    "bias": {
        "articles": ["article-15-4", "annex-iv-2-g"],
        "requirement": "Absence of Bias / Absence of Discrimination",
        "description": "Evaluation of demographic representation (Art. 15(4), Annex IV(2)(g))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Systems appropriate for intended purpose with examination of possible biases "
                      "that are likely to affect health and safety or fundamental rights.",
    },
    # =========================================================================
    # Harmful Content (Art. 9, Art. 95) - Toxicity, safety
    # =========================================================================
    "toxicity": {
        "articles": ["article-9", "article-95"],
        "requirement": "Harmful Content Prevention",
        "description": "Prevention of harmful/toxic content generation (Art. 9, Art. 95)",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Risk management system addressing foreseeable risks and societal well-being.",
    },
    "continuation": {
        "articles": ["article-9", "article-95"],
        "requirement": "Harmful Content Prevention",
        "description": "Prevention of harmful content continuation (Art. 9, Art. 95)",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Risk management for harmful content that may affect health and safety.",
    },
    "donotanswer": {
        "articles": ["article-9"],
        "requirement": "Harmful Content Prevention",
        "description": "Content moderation boundary testing (Art. 9)",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Risk management system for content that should be refused.",
    },
    "lmrc": {
        "articles": ["article-9", "article-95"],
        "requirement": "Harmful Content Prevention",
        "description": "Language model risk categories assessment (Art. 9, Art. 95)",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Comprehensive risk assessment for various harm categories.",
    },
    # =========================================================================
    # Cyberattack Resilience (Art. 15(5)) - Malware, XSS, attack generation
    # =========================================================================
    "manipulation": {
        "articles": ["article-15-5"],
        "requirement": "Cyberattack Resilience",
        "description": "Output integrity and manipulation resistance (Art. 15(5))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Resilience against attempts to alter outputs through exploitation.",
    },
    "xss": {
        "articles": ["article-15-5"],
        "requirement": "Cyberattack Resilience",
        "description": "Cross-site scripting and output injection resistance (Art. 15(5))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Resilience against model evasion attacks via output injection.",
    },
    "atkgen": {
        "articles": ["article-15-5"],
        "requirement": "Cyberattack Resilience",
        "description": "Resistance to automated attack generation (Art. 15(5))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Resilience against adversarial attack generation techniques.",
    },
    "gcg": {
        "articles": ["article-15-5"],
        "requirement": "Cyberattack Resilience",
        "description": "Resistance to gradient-based adversarial attacks (Art. 15(5))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Resilience against adversarial examples exploiting model gradients.",
    },
    "glitch": {
        "articles": ["article-15-5"],
        "requirement": "Cyberattack Resilience",
        "description": "Resistance to adversarial token attacks (Art. 15(5))",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Resilience against glitch/anomalous token exploitation.",
    },
    # =========================================================================
    # Accuracy & Interpretability (Art. 13, Art. 15) - Hallucination
    # =========================================================================
    "hallucination": {
        "articles": ["article-13-1", "article-15-1"],
        "requirement": "Accuracy / Interpretability",
        "description": "Factual accuracy and reliability evaluation (Art. 13(1), Art. 15(1))",
        "risk_level": RiskLevel.LIMITED,
        "legal_basis": "Appropriate level of accuracy, robustness and transparency in operation.",
    },
    "misleading": {
        "articles": ["article-13-1", "article-15-1"],
        "requirement": "Accuracy / Interpretability",
        "description": "Misinformation and false assertion testing (Art. 13(1), Art. 15(1))",
        "risk_level": RiskLevel.LIMITED,
        "legal_basis": "Accuracy and reliability requirements for AI system outputs.",
    },
    "packagehallucination": {
        "articles": ["article-13-1", "article-15-1"],
        "requirement": "Accuracy / Interpretability",
        "description": "Code generation accuracy testing (Art. 13(1), Art. 15(1))",
        "risk_level": RiskLevel.LIMITED,
        "legal_basis": "Accuracy requirements for code and technical outputs.",
    },
    "snowball": {
        "articles": ["article-13-1", "article-15-1"],
        "requirement": "Accuracy / Interpretability",
        "description": "Logical reasoning and deductive accuracy (Art. 13(1), Art. 15(1))",
        "risk_level": RiskLevel.LIMITED,
        "legal_basis": "Reliability and consistency in reasoning outputs.",
    },
    # =========================================================================
    # Transparency (Art. 13, Art. 50)
    # =========================================================================
    "transparency": {
        "articles": ["article-13", "article-50"],
        "requirement": "AI Disclosure / Capabilities",
        "description": "Testing transparency and disclosure requirements (Art. 13, Art. 50)",
        "risk_level": RiskLevel.LIMITED,
        "legal_basis": "Transparent operation and information provision to users.",
    },
    "compliance_transparency": {
        "articles": ["article-13", "article-50"],
        "requirement": "AI Disclosure / Capabilities",
        "description": "Verifying AI system transparency compliance (Art. 13, Art. 50)",
        "risk_level": RiskLevel.LIMITED,
        "legal_basis": "AI systems shall be designed to inform natural persons of AI interaction.",
    },
    # =========================================================================
    # Human Oversight (Art. 14)
    # =========================================================================
    "human_oversight": {
        "articles": ["article-14"],
        "requirement": "Corrigibility",
        "description": "Testing human oversight mechanisms (Art. 14)",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Systems designed to enable effective human oversight during use.",
    },
    "compliance_human_oversight": {
        "articles": ["article-14"],
        "requirement": "Corrigibility",
        "description": "Verifying human oversight compliance (Art. 14)",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Measures enabling individuals to oversee AI system functioning.",
    },
    # =========================================================================
    # Baseline & Comprehensive Testing
    # =========================================================================
    "goodside": {
        "articles": [],
        "requirement": "Baseline Testing",
        "description": "Baseline testing with known benign prompts",
        "risk_level": RiskLevel.MINIMAL,
        "legal_basis": "Baseline for comparison with adversarial testing.",
    },
    "comprehensive": {
        "articles": ["annex-iv"],
        "requirement": "Technical Documentation",
        "description": "Full technical documentation compliance (Annex IV)",
        "risk_level": RiskLevel.HIGH,
        "legal_basis": "Comprehensive technical documentation requirements per Annex IV.",
    },
}

# Default probes for each garak module
# Used when mapping a module without specific probe classes
# Note: These are the available probes in garak 0.13.x
DEFAULT_MODULE_PROBES: dict[str, list[str]] = {
    "promptinject": [
        "promptinject.HijackHateHumansMini",
        "promptinject.AutoDAN",
        "promptinject.HumanJailbreaks",
    ],
    "dan": [
        "dan.DAN",
        "dan.DUDE",
        "dan.DANJailbreak",
    ],
    "encoding": [
        "encoding.InjectBase64",
        "encoding.InjectHex",
        "encoding.InjectROT13",
        "encoding.InjectMorse",
    ],
    "leakreplay": [
        "leakreplay.LiteratureCloze",
        "leakreplay.GuardianCloze",
    ],
    "malwaregen": [
        "malwaregen.Evasion",
        "malwaregen.Payload",
        "malwaregen.SubFunctions",
    ],
    "atkgen": [
        "atkgen.Tox",
    ],
    "continuation": [
        "continuation.ContinueSlursReclaimedSlurs",
    ],
    "donotanswer": [
        "donotanswer.DiscriminationExclusionToxicityHatefulOffensive",
    ],
    "gcg": [
        "gcg.GCGCached",
    ],
    "glitch": [
        "glitch.Glitch",
    ],
    "goodside": [
        "goodside.Tag",
        "goodside.WhoIsRiley",
    ],
    "lmrc": [
        "lmrc.Bullying",
        "lmrc.Deadnaming",
        "lmrc.QuackMedicine",
        "lmrc.SexualContent",
        "lmrc.Sexualisation",
        "lmrc.SlurUsage",
    ],
    "misleading": [
        "misleading.FalseAssertion50",
    ],
    "packagehallucination": [
        "packagehallucination.Python",
    ],
    "realtoxicityprompts": [
        "realtoxicityprompts.RTPSevere_Toxicity",
    ],
    "snowball": [
        "snowball.GraphConnectivity",
        "snowball.Primes",
        "snowball.Senators",
    ],
    "xss": [
        "xss.MarkdownImageExfil",
    ],
}


# =============================================================================
# ProbeMapper Class
# =============================================================================


class ProbeMapper:
    """
    Maps SCI probe names to garak probe identifiers.

    This class provides methods to translate SCI's semantic probe names
    (e.g., "prompt_injection_basic") to garak's technical probe identifiers
    (e.g., "promptinject.HumanJailbreaks").

    Attributes:
        config: GarakConfig instance containing probe_categories mapping.
        logger: Structured logger for operations.

    Example:
        >>> config = GarakConfig(probe_categories={"prompt_injection_basic": "promptinject"})
        >>> mapper = ProbeMapper(config)
        >>> probes = mapper.map_probe_name("prompt_injection_basic")
        >>> print(probes)
        ['promptinject.HumanJailbreaks', 'promptinject.AutoDAN', ...]
    """

    def __init__(self, config: GarakConfig) -> None:
        """
        Initialize the probe mapper.

        Args:
            config: GarakConfig instance with probe_categories mapping.
        """
        self.config = config
        self.logger = get_logger(__name__)
        self._probe_cache: dict[str, list[str]] = {}

        self.logger.debug(
            "probe_mapper_initialized",
            probe_categories_count=len(config.probe_categories),
        )

    def map_probe_name(self, sci_probe_name: str) -> list[str]:
        """
        Map an SCI probe name to garak probe identifiers.

        Args:
            sci_probe_name: SCI probe name (e.g., "prompt_injection_basic").

        Returns:
            List of fully qualified garak probe identifiers
            (e.g., ["promptinject.HumanJailbreaks", "promptinject.AutoDAN"]).

        Raises:
            ValueError: If probe name not found and no fallback available.

        Example:
            >>> mapper.map_probe_name("prompt_injection_basic")
            ['promptinject.HumanJailbreaks', 'promptinject.AutoDAN', ...]
        """
        # Check cache first
        if sci_probe_name in self._probe_cache:
            return self._probe_cache[sci_probe_name]

        # Look up in config.probe_categories
        garak_module = self.config.probe_categories.get(sci_probe_name)

        if garak_module is None:
            # Try fallback: match by prefix in PROBE_MODULE_MAPPING
            garak_module = self._find_module_by_prefix(sci_probe_name)

        if garak_module is None:
            # Provide helpful error with suggestions
            suggestions = self._get_similar_probe_names(sci_probe_name)
            suggestion_msg = ""
            if suggestions:
                suggestion_msg = f" Did you mean: {', '.join(suggestions)}?"

            raise ValueError(
                f"Unknown SCI probe name: '{sci_probe_name}'.{suggestion_msg} "
                f"Available probes: {list(self.config.probe_categories.keys())}"
            )

        # Handle wildcard mappings (e.g., "promptinject.*")
        if garak_module.endswith(".*"):
            module_base = garak_module[:-2]
            probes = DEFAULT_MODULE_PROBES.get(module_base, [])
        else:
            # Get default probes for the module
            probes = DEFAULT_MODULE_PROBES.get(garak_module, [])

            # If no default probes defined, return module as wildcard pattern
            if not probes:
                probes = [f"{garak_module}.*"]

        self._probe_cache[sci_probe_name] = probes

        self.logger.debug(
            "probe_mapped",
            sci_probe_name=sci_probe_name,
            garak_module=garak_module,
            probe_count=len(probes),
        )

        return probes

    def map_probe_list(self, sci_probe_names: list[str]) -> list[str]:
        """
        Map multiple SCI probe names to garak identifiers.

        Args:
            sci_probe_names: List of SCI probe names.

        Returns:
            Sorted list of unique garak probe identifiers.

        Example:
            >>> mapper.map_probe_list(["prompt_injection_basic", "jailbreak_basic"])
            ['dan.ChatGPT_Developer_Mode', 'dan.DAN', 'dan.DUDE', ...]
        """
        all_probes: set[str] = set()

        for probe_name in sci_probe_names:
            try:
                probes = self.map_probe_name(probe_name)
                all_probes.update(probes)
            except ValueError as e:
                self.logger.warning(
                    "probe_mapping_failed",
                    probe_name=probe_name,
                    error=str(e),
                )

        return sorted(all_probes)

    def get_module_probes(
        self, module_name: str, client: GarakClient
    ) -> list[str]:
        """
        Get all probes from a specific garak module.

        Queries the client for available probes and filters by module name.

        Args:
            module_name: Garak module name (e.g., "promptinject").
            client: GarakClient instance for querying available probes.

        Returns:
            List of probe identifiers from the specified module.

        Example:
            >>> probes = mapper.get_module_probes("promptinject", client)
            >>> print(probes)
            ['promptinject.HumanJailbreaks', 'promptinject.AutoDAN', ...]
        """
        available_probes = client.list_available_probes()
        module_probes = [p for p in available_probes if p.startswith(f"{module_name}.")]

        self.logger.debug(
            "module_probes_retrieved",
            module_name=module_name,
            probe_count=len(module_probes),
        )

        return module_probes

    def validate_probe(self, probe_identifier: str, client: GarakClient) -> bool:
        """
        Validate that a probe identifier exists in garak.

        Args:
            probe_identifier: Garak probe identifier to validate.
            client: GarakClient instance for querying available probes.

        Returns:
            True if probe exists, False otherwise.

        Example:
            >>> mapper.validate_probe("promptinject.HumanJailbreaks", client)
            True
        """
        available_probes = client.list_available_probes()
        is_valid = probe_identifier in available_probes

        if not is_valid:
            self.logger.warning(
                "probe_validation_failed",
                probe_identifier=probe_identifier,
            )

        return is_valid

    def _find_module_by_prefix(self, probe_name: str) -> Optional[str]:
        """Find garak module by matching SCI probe name prefix."""
        # Extract prefix (e.g., "prompt_injection" from "prompt_injection_basic")
        for prefix, module in PROBE_MODULE_MAPPING.items():
            if probe_name.startswith(prefix):
                return module
        return None

    def _get_similar_probe_names(self, probe_name: str) -> list[str]:
        """Get similar probe names for error suggestions."""
        all_names = list(self.config.probe_categories.keys())
        return get_close_matches(probe_name, all_names, n=3, cutoff=0.5)


# =============================================================================
# DetectorMapper Class
# =============================================================================


class DetectorMapper:
    """
    Maps SCI detector names to garak detector identifiers and configurations.

    This class provides methods to translate SCI's semantic detector names
    (e.g., "toxicity_basic") to garak's detector configurations.

    Attributes:
        config: GarakConfig instance.
        logger: Structured logger for operations.

    Example:
        >>> config = GarakConfig()
        >>> mapper = DetectorMapper(config)
        >>> detectors = mapper.map_detector_name("toxicity_basic")
        >>> print(detectors)
        ['detectors.toxicity.ToxicCommentModel']
    """

    def __init__(self, config: GarakConfig) -> None:
        """
        Initialize the detector mapper.

        Args:
            config: GarakConfig instance.
        """
        self.config = config
        self.logger = get_logger(__name__)

        self.logger.debug("detector_mapper_initialized")

    def map_detector_name(self, sci_detector_name: str) -> list[str]:
        """
        Map an SCI detector name to garak detector identifiers.

        Args:
            sci_detector_name: SCI detector name (e.g., "toxicity_basic").

        Returns:
            List of garak detector identifiers.

        Raises:
            ValueError: If detector name not found.

        Example:
            >>> mapper.map_detector_name("toxicity_basic")
            ['detectors.toxicity.ToxicCommentModel']
        """
        detector_config = DETECTOR_TYPE_MAPPING.get(sci_detector_name)

        if detector_config is None:
            # Try prefix matching
            detector_config = self._find_detector_by_prefix(sci_detector_name)

        if detector_config is None:
            suggestions = self._get_similar_detector_names(sci_detector_name)
            suggestion_msg = ""
            if suggestions:
                suggestion_msg = f" Did you mean: {', '.join(suggestions)}?"

            raise ValueError(
                f"Unknown SCI detector name: '{sci_detector_name}'.{suggestion_msg} "
                f"Available detectors: {list(DETECTOR_TYPE_MAPPING.keys())}"
            )

        detectors = detector_config.get("detectors", [])

        self.logger.debug(
            "detector_mapped",
            sci_detector_name=sci_detector_name,
            detector_count=len(detectors),
        )

        return detectors

    def map_detector_list(self, sci_detector_names: list[str]) -> list[str]:
        """
        Map multiple SCI detector names to garak identifiers.

        Args:
            sci_detector_names: List of SCI detector names.

        Returns:
            Sorted list of unique garak detector identifiers.

        Example:
            >>> mapper.map_detector_list(["toxicity_basic", "leakage_basic"])
            ['detectors.leakage.TriggerListDetector', 'detectors.toxicity.ToxicCommentModel']
        """
        all_detectors: set[str] = set()

        for detector_name in sci_detector_names:
            try:
                detectors = self.map_detector_name(detector_name)
                all_detectors.update(detectors)
            except ValueError as e:
                self.logger.warning(
                    "detector_mapping_failed",
                    detector_name=detector_name,
                    error=str(e),
                )

        return sorted(all_detectors)

    def get_detector_config(self, sci_detector_name: str) -> dict[str, Any]:
        """
        Get the full configuration for a detector.

        Args:
            sci_detector_name: SCI detector name.

        Returns:
            Configuration dictionary including detector type, threshold,
            extended mode flag, and other settings.

        Example:
            >>> config = mapper.get_detector_config("toxicity_basic")
            >>> print(config)
            {'detectors': [...], 'level': 'basic', 'threshold': 0.5}
        """
        detector_config = DETECTOR_TYPE_MAPPING.get(sci_detector_name)

        if detector_config is None:
            detector_config = self._find_detector_by_prefix(sci_detector_name)

        if detector_config is None:
            return {
                "detectors": [],
                "level": "unknown",
                "threshold": 0.5,
            }

        return dict(detector_config)

    def _find_detector_by_prefix(
        self, detector_name: str
    ) -> Optional[dict[str, Any]]:
        """Find detector config by matching prefix."""
        for name, config in DETECTOR_TYPE_MAPPING.items():
            # Match if detector_name starts with the same category
            if detector_name.split("_")[0] == name.split("_")[0]:
                return config
        return None

    def _get_similar_detector_names(self, detector_name: str) -> list[str]:
        """Get similar detector names for error suggestions."""
        all_names = list(DETECTOR_TYPE_MAPPING.keys())
        return get_close_matches(detector_name, all_names, n=3, cutoff=0.5)


# =============================================================================
# ComplianceMapper Class
# =============================================================================


class ComplianceMapper:
    """
    Maps probes and detectors to EU AI Act compliance requirements.

    This class provides methods to associate security testing activities
    with specific EU AI Act articles and annexes, enabling compliance
    reporting and risk assessment.

    The mappings are based on the COMPL-AI Framework (arXiv:2410.07959) which
    provides academically-grounded interpretation of EU AI Act requirements.
    Article references include paragraph-level specificity (e.g., "article-15-5"
    for Cyberattack Resilience).

    Example:
        >>> mapper = ComplianceMapper()
        >>> articles = mapper.get_articles_for_probe("prompt_injection_basic")
        >>> print(articles)
        ['article-15-5']  # Cyberattack Resilience per COMPL-AI
    """

    def __init__(self) -> None:
        """Initialize the compliance mapper."""
        self.logger = get_logger(__name__)
        self.logger.debug("compliance_mapper_initialized")

    def get_articles_for_probe(self, probe_name: str) -> list[str]:
        """
        Get EU AI Act articles relevant to a probe category.

        Args:
            probe_name: SCI probe name (e.g., "prompt_injection_basic").

        Returns:
            List of article identifiers with paragraph-level specificity
            (e.g., ["article-15-5"] for Cyberattack Resilience).

        Example:
            >>> mapper.get_articles_for_probe("prompt_injection_basic")
            ['article-15-5']  # Cyberattack Resilience
        """
        category = self._extract_category(probe_name)
        mapping = EU_AI_ACT_MAPPING.get(category, {})
        return mapping.get("articles", [])

    def get_articles_for_detector(self, detector_name: str) -> list[str]:
        """
        Get EU AI Act articles relevant to a detector category.

        Args:
            detector_name: SCI detector name (e.g., "toxicity_basic").

        Returns:
            List of article identifiers.

        Example:
            >>> mapper.get_articles_for_detector("toxicity_basic")
            ['article-9']
        """
        category = self._extract_category(detector_name)
        mapping = EU_AI_ACT_MAPPING.get(category, {})
        return mapping.get("articles", [])

    def get_compliance_tags(
        self,
        probes: list[str],
        detectors: list[str],
    ) -> list[str]:
        """
        Aggregate compliance tags for probes and detectors.

        Args:
            probes: List of SCI probe names.
            detectors: List of SCI detector names.

        Returns:
            Unique sorted list of all applicable articles and annexes,
            with paragraph-level specificity per COMPL-AI Framework.

        Example:
            >>> tags = mapper.get_compliance_tags(
            ...     ["prompt_injection_basic", "extraction_system_prompt"],
            ...     ["toxicity_basic", "leakage_basic"]
            ... )
            >>> print(tags)
            ['article-9', 'article-10', 'article-15-5', 'article-53-1-c']
        """
        all_tags: set[str] = set()

        for probe in probes:
            articles = self.get_articles_for_probe(probe)
            all_tags.update(articles)

        for detector in detectors:
            articles = self.get_articles_for_detector(detector)
            all_tags.update(articles)

        # Sort with articles before annexes
        def sort_key(tag: str) -> tuple[int, str]:
            if tag.startswith("article-"):
                return (0, tag)
            elif tag.startswith("annex-"):
                return (1, tag)
            return (2, tag)

        return sorted(all_tags, key=sort_key)

    def get_risk_category(self, probe_name: str) -> RiskLevel:
        """
        Determine EU AI Act risk level for a probe category.

        Args:
            probe_name: SCI probe name.

        Returns:
            RiskLevel enum value (minimal, limited, high, unacceptable).

        Example:
            >>> mapper.get_risk_category("prompt_injection_basic")
            <RiskLevel.HIGH: 'high'>
        """
        category = self._extract_category(probe_name)
        mapping = EU_AI_ACT_MAPPING.get(category, {})
        return mapping.get("risk_level", RiskLevel.MINIMAL)

    def get_compliance_description(self, category: str) -> str:
        """
        Get human-readable description of compliance requirement.

        Args:
            category: Probe/detector category.

        Returns:
            Description string explaining the compliance context.

        Example:
            >>> mapper.get_compliance_description("prompt_injection")
            'Testing robustness against adversarial inputs'
        """
        mapping = EU_AI_ACT_MAPPING.get(category, {})
        return mapping.get("description", "No description available")

    def _extract_category(self, name: str) -> str:
        """Extract category from probe/detector name."""
        # Try exact match first
        if name in EU_AI_ACT_MAPPING:
            return name

        # Try prefix matching
        for category in EU_AI_ACT_MAPPING:
            if name.startswith(category):
                return category

        # Extract first part before underscore (e.g., "toxicity" from "toxicity_basic")
        base_category = name.split("_")[0]
        if base_category in EU_AI_ACT_MAPPING:
            return base_category

        return "comprehensive"  # Default fallback


# =============================================================================
# Utility Functions
# =============================================================================


def list_available_probes(client: GarakClient) -> dict[str, list[str]]:
    """
    List available garak probes grouped by module.

    Args:
        client: GarakClient instance.

    Returns:
        Dictionary mapping module names to lists of probe identifiers.

    Example:
        >>> probes_by_module = list_available_probes(client)
        >>> print(probes_by_module["promptinject"])
        ['promptinject.HumanJailbreaks', 'promptinject.AutoDAN', ...]
    """
    logger = get_logger(__name__)
    probes = client.list_available_probes()

    grouped: dict[str, list[str]] = {}
    for probe in probes:
        if "." in probe:
            module = probe.split(".")[0]
        else:
            module = "unknown"

        if module not in grouped:
            grouped[module] = []
        grouped[module].append(probe)

    logger.debug(
        "probes_grouped",
        module_count=len(grouped),
        total_probes=len(probes),
    )

    return grouped


@lru_cache(maxsize=1)
def list_available_detectors(client: GarakClient) -> list[str]:
    """
    List available garak detectors.

    Args:
        client: GarakClient instance.

    Returns:
        List of detector identifiers.

    Note:
        Results are cached for performance.
    """
    logger = get_logger(__name__)

    # Currently return known detector types from mapping
    # In future, this could query garak directly
    all_detectors: set[str] = set()
    for config in DETECTOR_TYPE_MAPPING.values():
        all_detectors.update(config.get("detectors", []))

    detectors = sorted(all_detectors)

    logger.debug(
        "detectors_listed",
        detector_count=len(detectors),
    )

    return detectors


def get_probe_description(probe_identifier: str) -> str:
    """
    Get human-readable description of a garak probe.

    Args:
        probe_identifier: Garak probe identifier (e.g., "promptinject.HumanJailbreaks").

    Returns:
        Human-readable description string.

    Example:
        >>> get_probe_description("promptinject.HumanJailbreaks")
        'Prompt injection probe using human-crafted jailbreak attempts'
    """
    # Probe descriptions based on module and class name
    descriptions: dict[str, str] = {
        "promptinject": "Prompt injection probe testing for unauthorized instruction injection",
        "dan": "Jailbreak probe using DAN (Do Anything Now) style attacks",
        "encoding": "Encoding-based jailbreak probe using various text encoding methods",
        "leakreplay": "Data extraction probe testing for training data leakage",
        "malwaregen": "Malware generation probe testing for harmful code generation",
        "atkgen": "Attack generation probe using automated adversarial techniques",
        "continuation": "Text continuation probe testing for harmful completions",
        "donotanswer": "Refusal probe testing content moderation boundaries",
        "gcg": "Gradient-based adversarial probe using GCG attack method",
        "glitch": "Adversarial token probe using glitch/anomalous tokens",
        "goodside": "Baseline probe using known benign prompts",
        "lmrc": "Language model risk card probe testing various harm categories",
        "misleading": "Misinformation probe testing factual accuracy",
        "packagehallucination": "Package hallucination probe testing code generation accuracy",
        "realtoxicityprompts": "Toxicity probe using RealToxicityPrompts dataset",
        "snowball": "Logical reasoning probe testing deductive capabilities",
        "xss": "Cross-site scripting probe testing output sanitization",
    }

    if "." in probe_identifier:
        module = probe_identifier.split(".")[0]
    else:
        module = probe_identifier

    base_description = descriptions.get(module, f"Security probe from {module} module")

    # Add class-specific details if available
    if "." in probe_identifier:
        class_name = probe_identifier.split(".")[1]
        return f"{base_description} ({class_name})"

    return base_description


def get_detector_description(detector_identifier: str) -> str:
    """
    Get human-readable description of a garak detector.

    Args:
        detector_identifier: Garak detector identifier.

    Returns:
        Human-readable description string.

    Example:
        >>> get_detector_description("detectors.toxicity.ToxicCommentModel")
        'Toxicity detector using toxic comment classification model'
    """
    descriptions: dict[str, str] = {
        "toxicity": "Toxicity detector analyzing harmful or offensive content",
        "leakage": "Leakage detector identifying sensitive information disclosure",
        "bias": "Bias detector evaluating demographic and social biases",
        "hallucination": "Hallucination detector checking factual consistency",
        "compliance": "Compliance detector validating regulatory requirements",
    }

    # Extract detector category from identifier
    parts = detector_identifier.split(".")
    if len(parts) >= 2:
        category = parts[-2] if parts[-2] != "detectors" else parts[-1].lower()
    else:
        category = detector_identifier.lower()

    for key, desc in descriptions.items():
        if key in category.lower():
            return desc

    return f"Security detector: {detector_identifier}"


def validate_mappings(
    config: GarakConfig, client: GarakClient
) -> dict[str, Any]:
    """
    Validate all probe_categories mappings in config.

    Args:
        config: GarakConfig with probe_categories to validate.
        client: GarakClient for querying available probes.

    Returns:
        Validation report with:
        - valid_mappings: List of valid probe name → module mappings
        - invalid_mappings: List of mappings with unavailable modules
        - warnings: List of warning messages
        - available_modules: List of modules available in garak

    Example:
        >>> report = validate_mappings(config, client)
        >>> print(report["invalid_mappings"])
        []
    """
    logger = get_logger(__name__)

    # Get available probes and extract modules
    available_probes = client.list_available_probes()
    available_modules = {p.split(".")[0] for p in available_probes if "." in p}

    valid_mappings: list[dict[str, str]] = []
    invalid_mappings: list[dict[str, Any]] = []
    warnings: list[str] = []

    for sci_name, garak_module in config.probe_categories.items():
        # Handle wildcard notation
        module_name = garak_module.rstrip(".*")

        if module_name in available_modules:
            valid_mappings.append({"sci_name": sci_name, "garak_module": garak_module})
        else:
            invalid_mappings.append({
                "sci_name": sci_name,
                "garak_module": garak_module,
                "reason": f"Module '{module_name}' not found in available probes",
            })
            warnings.append(
                f"Probe mapping '{sci_name}' → '{garak_module}' references "
                f"unavailable module '{module_name}'"
            )

    report = {
        "valid_mappings": valid_mappings,
        "invalid_mappings": invalid_mappings,
        "warnings": warnings,
        "available_modules": sorted(available_modules),
        "total_mappings": len(config.probe_categories),
        "valid_count": len(valid_mappings),
        "invalid_count": len(invalid_mappings),
    }

    logger.info(
        "mappings_validated",
        valid_count=len(valid_mappings),
        invalid_count=len(invalid_mappings),
    )

    return report


# =============================================================================
# Reverse Mapping Functions
# =============================================================================


def get_sci_probe_name(garak_probe: str, config: GarakConfig) -> Optional[str]:
    """
    Get SCI probe name for a garak probe identifier.

    Args:
        garak_probe: Garak probe identifier (e.g., "promptinject.HumanJailbreaks").
        config: GarakConfig with probe_categories mapping.

    Returns:
        SCI probe name or None if not found.

    Example:
        >>> get_sci_probe_name("promptinject.HumanJailbreaks", config)
        'prompt_injection_basic'
    """
    if "." not in garak_probe:
        return None

    module = garak_probe.split(".")[0]

    # Search through probe_categories for matching module
    for sci_name, garak_module in config.probe_categories.items():
        if garak_module.rstrip(".*") == module:
            return sci_name

    # Fallback: search PROBE_MODULE_MAPPING
    for prefix, mapped_module in PROBE_MODULE_MAPPING.items():
        if mapped_module == module:
            # Return first matching SCI probe name from config
            for sci_name in config.probe_categories:
                if sci_name.startswith(prefix):
                    return sci_name
            # Return generic name based on prefix
            return f"{prefix}_basic"

    return None


def get_sci_detector_name(garak_detector: str) -> Optional[str]:
    """
    Get SCI detector name for a garak detector identifier.

    Args:
        garak_detector: Garak detector identifier.

    Returns:
        SCI detector name or None if not found.

    Example:
        >>> get_sci_detector_name("detectors.toxicity.ToxicCommentModel")
        'toxicity_basic'
    """
    # Search through DETECTOR_TYPE_MAPPING
    for sci_name, config in DETECTOR_TYPE_MAPPING.items():
        if garak_detector in config.get("detectors", []):
            return sci_name

    return None


# =============================================================================
# Mapping Configuration Helpers
# =============================================================================


def generate_default_probe_mapping() -> dict[str, str]:
    """
    Generate default probe_categories mapping.

    Returns:
        Dictionary matching the structure in defaults.py.

    Example:
        >>> mapping = generate_default_probe_mapping()
        >>> print(mapping["prompt_injection_basic"])
        'promptinject'
    """
    return {
        # Prompt injection probes
        "prompt_injection_basic": "promptinject",
        "prompt_injection_advanced": "promptinject",
        "prompt_injection_multilingual": "promptinject",
        # Jailbreak probes
        "jailbreak_basic": "dan",
        "jailbreak_roleplay": "dan",
        "jailbreak_encoding": "encoding",
        # Extraction probes
        "extraction_system_prompt": "leakreplay",
        "extraction_training_data": "leakreplay",
        "extraction_model_info": "leakreplay",
        # Manipulation probes
        "manipulation_output": "malwaregen",
        "manipulation_context": "malwaregen",
        # Compliance probes
        "compliance_transparency": "lmrc",
        "compliance_human_oversight": "lmrc",
    }


def extend_probe_mapping(
    base_mapping: dict[str, str],
    custom_mapping: dict[str, str],
) -> dict[str, str]:
    """
    Extend base probe mapping with custom mappings.

    Custom mappings override base mappings for the same keys.

    Args:
        base_mapping: Base probe_categories mapping.
        custom_mapping: Custom mappings to add/override.

    Returns:
        Combined mapping dictionary.

    Example:
        >>> base = {"probe_a": "module_a"}
        >>> custom = {"probe_b": "module_b", "probe_a": "module_c"}
        >>> result = extend_probe_mapping(base, custom)
        >>> print(result)
        {'probe_a': 'module_c', 'probe_b': 'module_b'}
    """
    combined = dict(base_mapping)
    combined.update(custom_mapping)
    return combined


def get_all_compliance_articles() -> list[str]:
    """
    Get all unique EU AI Act articles referenced in mappings.

    Returns:
        Sorted list of article identifiers with paragraph-level specificity.

    Example:
        >>> articles = get_all_compliance_articles()
        >>> print(articles)
        ['article-9', 'article-10', 'article-13-1', 'article-14', 'article-15-1', 'article-15-4', 'article-15-5', ...]
    """
    all_articles: set[str] = set()

    for mapping in EU_AI_ACT_MAPPING.values():
        all_articles.update(mapping.get("articles", []))

    # Sort with proper ordering (handles paragraph-level specificity like "article-15-5")
    def sort_key(article: str) -> tuple[int, int, int, str]:
        if article.startswith("article-"):
            parts = article.split("-")
            # Extract article number
            article_num = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            # Extract paragraph number if present (e.g., "15-5" -> 5, "15-1-d" -> 1)
            paragraph_num = 0
            sub_paragraph = ""
            if len(parts) > 2:
                if parts[2].isdigit():
                    paragraph_num = int(parts[2])
                else:
                    sub_paragraph = parts[2]
            if len(parts) > 3:
                sub_paragraph = parts[3]
            return (0, article_num, paragraph_num, sub_paragraph)
        elif article.startswith("annex-"):
            # Convert Roman numerals to numbers for sorting
            parts = article.split("-")
            numeral = parts[1].upper() if len(parts) > 1 else ""
            roman_values = {"I": 1, "II": 2, "III": 3, "IV": 4, "V": 5, "VI": 6}
            annex_num = roman_values.get(numeral, 99)
            # Handle sub-sections like "annex-iv-2-g"
            section_num = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
            sub_section = parts[3] if len(parts) > 3 else ""
            return (1, annex_num, section_num, sub_section)
        return (2, 0, 0, "")

    return sorted(all_articles, key=sort_key)


def get_probes_for_article(article: str) -> list[str]:
    """
    Get all probe categories relevant to an EU AI Act article.

    Supports both general article matching (e.g., "article-15" matches
    "article-15-1", "article-15-4", "article-15-5") and exact matching.

    Args:
        article: Article identifier (e.g., "article-15" or "article-15-5").

    Returns:
        List of probe category names.

    Example:
        >>> probes = get_probes_for_article("article-15-5")
        >>> print(probes)
        ['prompt_injection', 'jailbreak', 'manipulation', 'xss', 'atkgen', 'gcg', 'glitch']
    """
    relevant_probes: list[str] = []

    for category, mapping in EU_AI_ACT_MAPPING.items():
        articles = mapping.get("articles", [])
        # Check for exact match or prefix match (e.g., "article-15" matches "article-15-5")
        for mapped_article in articles:
            if article == mapped_article or mapped_article.startswith(f"{article}-"):
                relevant_probes.append(category)
                break

    return sorted(relevant_probes)


def get_requirement_for_category(category: str) -> dict[str, Any]:
    """
    Get the COMPL-AI technical requirement information for a probe category.

    Args:
        category: Probe/detector category name.

    Returns:
        Dictionary containing:
        - requirement: COMPL-AI technical requirement name
        - articles: List of relevant EU AI Act articles
        - description: Human-readable description
        - legal_basis: Legal text justification (if available)

    Example:
        >>> info = get_requirement_for_category("prompt_injection")
        >>> print(info["requirement"])
        'Cyberattack Resilience'
        >>> print(info["articles"])
        ['article-15-5']
    """
    mapping = EU_AI_ACT_MAPPING.get(category, {})

    return {
        "requirement": mapping.get("requirement", "Unknown"),
        "articles": mapping.get("articles", []),
        "description": mapping.get("description", "No description available"),
        "legal_basis": mapping.get("legal_basis", ""),
        "risk_level": mapping.get("risk_level", RiskLevel.MINIMAL),
    }


def get_compl_ai_requirement(requirement_name: str) -> dict[str, Any]:
    """
    Get detailed COMPL-AI requirement information by name.

    Args:
        requirement_name: COMPL-AI requirement name (e.g., "cyberattack_resilience").

    Returns:
        Dictionary with full requirement details from COMPL_AI_REQUIREMENTS,
        or empty dict if not found.

    Example:
        >>> req = get_compl_ai_requirement("cyberattack_resilience")
        >>> print(req["principle"])
        'Technical Robustness & Safety'
        >>> print(req["articles"])
        ['article-15-5', 'article-55-1-d']
    """
    return dict(COMPL_AI_REQUIREMENTS.get(requirement_name, {}))
