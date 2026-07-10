"""
ML-based Content Classification Service
=========================================
Provides NLP/ML-powered content classification that works alongside
the existing regex/keyword/dictionary engine to reduce false positives
and detect sensitive content in context.

Architecture:
- spaCy NER: Named entity recognition for PII detection in context
- TF-IDF + SGD Classifier: Document sensitivity classification
- Runs inside the Manager process (no separate container)
- Loaded once on startup, cached in memory
- Falls back gracefully if models unavailable
"""

import asyncio
import os
import pickle
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import structlog

logger = structlog.get_logger()

# Lazy imports to avoid startup penalty if ML deps are missing
_spacy_nlp = None
_tfidf_vectorizer = None
_sensitivity_classifier = None
_ml_ready = False


# --- Model Paths ---
MODEL_DIR = Path(os.getenv("ML_MODEL_DIR", "/app/ml_models"))
CUSTOM_MODEL_PATH = MODEL_DIR / "sensitivity_classifier.pkl"
TFIDF_PATH = MODEL_DIR / "tfidf_vectorizer.pkl"


class SensitivityLabel:
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# PII Entity Weights (spaCy + custom)
PII_ENTITY_WEIGHTS = {
    # spaCy built-in entities
    "PERSON": 0.3,
    "ORG": 0.1,
    "GPE": 0.05,
    "DATE": 0.05,
    "MONEY": 0.2,
    "CARDINAL": 0.05,
    # Custom entities
    "SSN": 0.9,
    "CREDIT_CARD": 0.9,
    "EMAIL_ADDRESS": 0.3,
    "PHONE_NUMBER": 0.25,
    "AADHAAR": 0.85,
    "PAN_CARD": 0.8,
    "BANK_ACCOUNT": 0.75,
    "API_KEY": 0.85,
    "PASSWORD": 0.9,
    "PRIVATE_KEY": 0.95,
    "DATABASE_URI": 0.85,
    "IP_ADDRESS": 0.15,
    "AWS_KEY": 0.9,
    "GITHUB_TOKEN": 0.9,
}


def _load_spacy():
    """Load spaCy model lazily."""
    global _spacy_nlp
    if _spacy_nlp is not None:
        return _spacy_nlp

    try:
        import spacy
        try:
            _spacy_nlp = spacy.load("en_core_web_sm")
        except OSError:
            logger.info("Downloading spaCy model en_core_web_sm...")
            from spacy.cli import download
            download("en_core_web_sm")
            _spacy_nlp = spacy.load("en_core_web_sm")

        logger.info("spaCy NER model loaded successfully")
        return _spacy_nlp

    except ImportError:
        logger.warning("spaCy not installed - NER will be disabled")
        return None
    except Exception as e:
        logger.error("Failed to load spaCy model", error=str(e))
        return None


def _load_sensitivity_classifier():
    """Load the TF-IDF + classifier pipeline."""
    global _tfidf_vectorizer, _sensitivity_classifier

    if _tfidf_vectorizer is not None:
        return _tfidf_vectorizer, _sensitivity_classifier

    # Try loading pre-trained model from disk
    if CUSTOM_MODEL_PATH.exists() and TFIDF_PATH.exists():
        try:
            with open(TFIDF_PATH, "rb") as f:
                _tfidf_vectorizer = pickle.load(f)
            with open(CUSTOM_MODEL_PATH, "rb") as f:
                _sensitivity_classifier = pickle.load(f)
            logger.info("Custom sensitivity classifier loaded from disk")
            return _tfidf_vectorizer, _sensitivity_classifier
        except Exception as e:
            logger.warning("Failed to load custom model, using default", error=str(e))

    # Build default classifier
    _tfidf_vectorizer, _sensitivity_classifier = _build_default_classifier()
    return _tfidf_vectorizer, _sensitivity_classifier


def _build_default_classifier():
    """
    Build a default TF-IDF + SGDClassifier trained on synthetic
    DLP-relevant examples. Gives reasonable baseline accuracy
    until the customer trains on their own data.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import SGDClassifier

    training_data = [
        # PUBLIC (examples, docs, training materials)
        ("Welcome to our company. We are located in New York.", SensitivityLabel.PUBLIC),
        ("The meeting is scheduled for Monday at 10am.", SensitivityLabel.PUBLIC),
        ("Please find the agenda attached for the weekly sync.", SensitivityLabel.PUBLIC),
        ("Our office hours are 9am to 5pm.", SensitivityLabel.PUBLIC),
        ("SSN format is XXX-XX-XXXX where X is a digit.", SensitivityLabel.PUBLIC),
        ("Credit card numbers typically start with 4 for Visa.", SensitivityLabel.PUBLIC),
        ("Example: 4111-1111-1111-1111 is a test card number.", SensitivityLabel.PUBLIC),
        ("PAN card format: ABCDE1234F (5 letters, 4 digits, 1 letter).", SensitivityLabel.PUBLIC),
        ("Aadhaar is a 12-digit identity number issued by UIDAI.", SensitivityLabel.PUBLIC),
        ("Documentation for regex patterns used in validation.", SensitivityLabel.PUBLIC),
        ("Unit test: assert validate_ssn('000-00-0000') == False.", SensitivityLabel.PUBLIC),
        ("Here is a tutorial on how credit card validation works.", SensitivityLabel.PUBLIC),
        ("The Luhn algorithm checks if a card number is valid.", SensitivityLabel.PUBLIC),
        ("Test data: use 123-45-6789 as a placeholder SSN.", SensitivityLabel.PUBLIC),
        ("README: This project validates Indian identity documents.", SensitivityLabel.PUBLIC),

        # INTERNAL (business data, not PII)
        ("Q3 revenue was $2.5M, up 15% from last quarter.", SensitivityLabel.INTERNAL),
        ("The new feature rollout is planned for sprint 24.", SensitivityLabel.INTERNAL),
        ("Team headcount: 12 engineers, 3 designers, 2 PMs.", SensitivityLabel.INTERNAL),
        ("Our AWS monthly bill is approximately $15,000.", SensitivityLabel.INTERNAL),
        ("Internal roadmap: finish auth module by end of month.", SensitivityLabel.INTERNAL),
        ("Architecture decision: switching from MySQL to PostgreSQL.", SensitivityLabel.INTERNAL),
        ("Bug rate is 2.3 per sprint, target is below 1.5.", SensitivityLabel.INTERNAL),
        ("Hiring plan: 5 new engineers in Q4.", SensitivityLabel.INTERNAL),
        ("Sprint velocity averaging 42 points per iteration.", SensitivityLabel.INTERNAL),
        ("Server costs breakdown by region and service.", SensitivityLabel.INTERNAL),

        # CONFIDENTIAL (business-sensitive, HR, customer data)
        ("Employee salary: John Smith earns $145,000 per year.", SensitivityLabel.CONFIDENTIAL),
        ("Performance review: Sarah needs improvement in leadership.", SensitivityLabel.CONFIDENTIAL),
        ("Customer list with 500 enterprise accounts and ARR.", SensitivityLabel.CONFIDENTIAL),
        ("Acquisition target: Company X valued at $50M.", SensitivityLabel.CONFIDENTIAL),
        ("Board meeting minutes: discussed potential layoffs.", SensitivityLabel.CONFIDENTIAL),
        ("Competitive analysis: their product lacks feature X.", SensitivityLabel.CONFIDENTIAL),
        ("Pricing strategy: increase enterprise tier by 20%.", SensitivityLabel.CONFIDENTIAL),
        ("Customer churn data: 5 enterprise accounts at risk.", SensitivityLabel.CONFIDENTIAL),
        ("Investor deck: Series B at $100M valuation.", SensitivityLabel.CONFIDENTIAL),
        ("Employee personal data: date of birth, home address.", SensitivityLabel.CONFIDENTIAL),
        ("Medical records show patient has diabetes type 2.", SensitivityLabel.CONFIDENTIAL),
        ("Termination list for Q4 restructuring.", SensitivityLabel.CONFIDENTIAL),

        # RESTRICTED (actual PII, credentials, secrets)
        ("My social security number is 123-45-6789.", SensitivityLabel.RESTRICTED),
        ("Credit card: 4532-1234-5678-9012 exp 12/25 CVV 123.", SensitivityLabel.RESTRICTED),
        ("Password for production database: P@ssw0rd!2024.", SensitivityLabel.RESTRICTED),
        ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE.", SensitivityLabel.RESTRICTED),
        ("Patient SSN 987-65-4321, diagnosed with HIV positive.", SensitivityLabel.RESTRICTED),
        ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB private key follows.", SensitivityLabel.RESTRICTED),
        ("Database connection: postgresql://admin:secret@prod-db:5432/main.", SensitivityLabel.RESTRICTED),
        ("API secret key: sk_live_4eC39HqLyjWDarjtT1zdp7dc.", SensitivityLabel.RESTRICTED),
        ("Aadhaar number: 1234 5678 9012, linked to bank account.", SensitivityLabel.RESTRICTED),
        ("PAN: ABCDE1234F, annual income Rs 50 lakhs.", SensitivityLabel.RESTRICTED),
        ("Root password: admin123! for server 192.168.1.100.", SensitivityLabel.RESTRICTED),
        ("GitHub token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef.", SensitivityLabel.RESTRICTED),
        ("Here is the complete customer database export with PII.", SensitivityLabel.RESTRICTED),
        ("List of all employee SSNs for payroll processing.", SensitivityLabel.RESTRICTED),
        ("Encryption master key: 0x4A6F686E446F65536563726574.", SensitivityLabel.RESTRICTED),
        ("My Aadhaar is 9876 5432 1098 and PAN is BXYPK1234M.", SensitivityLabel.RESTRICTED),
    ]

    texts = [t[0] for t in training_data]
    labels = [t[1] for t in training_data]

    vectorizer = TfidfVectorizer(
        max_features=10000,
        ngram_range=(1, 3),
        stop_words="english",
        sublinear_tf=True,
        min_df=1,
    )

    classifier = SGDClassifier(
        loss="modified_huber",  # Gives probability estimates
        alpha=0.0001,
        max_iter=1000,
        random_state=42,
        class_weight="balanced",
    )

    X = vectorizer.fit_transform(texts)
    classifier.fit(X, labels)

    # Save for next restart
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(TFIDF_PATH, "wb") as f:
            pickle.dump(vectorizer, f)
        with open(CUSTOM_MODEL_PATH, "wb") as f:
            pickle.dump(classifier, f)
        logger.info("Default sensitivity classifier trained and saved")
    except Exception as e:
        logger.warning("Could not save classifier to disk", error=str(e))

    return vectorizer, classifier


class MLClassificationResult:
    """Result from ML classification pipeline."""

    def __init__(
        self,
        ml_confidence: float,
        predicted_label: str,
        entities_detected: List[Dict],
        context_flags: List[str],
        is_false_positive: bool,
        processing_time_ms: float,
        explanation: str,
    ):
        self.ml_confidence = ml_confidence
        self.predicted_label = predicted_label
        self.entities_detected = entities_detected
        self.context_flags = context_flags
        self.is_false_positive = is_false_positive
        self.processing_time_ms = processing_time_ms
        self.explanation = explanation

    def to_dict(self) -> Dict:
        return {
            "ml_confidence": round(self.ml_confidence, 4),
            "predicted_label": self.predicted_label,
            "entities_detected": self.entities_detected,
            "context_flags": self.context_flags,
            "is_false_positive": self.is_false_positive,
            "processing_time_ms": round(self.processing_time_ms, 2),
            "explanation": self.explanation,
        }


class MLClassificationService:
    """
    ML-based content classification service.
    Singleton: one instance per process, models loaded once.
    Thread-safe: inference is read-only.
    """

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._nlp = None
        self._vectorizer = None
        self._classifier = None
        self._ready = False

    async def initialize(self):
        """Load models asynchronously on first use."""
        if self._ready:
            return

        loop = asyncio.get_event_loop()
        start = time.time()

        try:
            self._nlp = await loop.run_in_executor(None, _load_spacy)
            self._vectorizer, self._classifier = await loop.run_in_executor(
                None, _load_sensitivity_classifier
            )
            self._ready = True
            logger.info(
                "ML Classification Service initialized",
                load_time_ms=round((time.time() - start) * 1000, 2),
                spacy_loaded=self._nlp is not None,
                classifier_loaded=self._classifier is not None,
            )
        except Exception as e:
            logger.error("ML init failed", error=str(e))
            self._ready = False

    @property
    def is_ready(self) -> bool:
        return self._ready

    async def classify(
        self,
        content: str,
        content_type: str = "text",
        metadata: Optional[Dict] = None,
    ) -> MLClassificationResult:
        """
        Run ML classification on content.
        Returns MLClassificationResult with confidence, entities, and flags.
        """
        start_time = time.time()

        if not self._ready:
            await self.initialize()

        if not self._ready:
            return MLClassificationResult(
                ml_confidence=0.0,
                predicted_label=SensitivityLabel.PUBLIC,
                entities_detected=[],
                context_flags=["ml_unavailable"],
                is_false_positive=False,
                processing_time_ms=0.0,
                explanation="ML service unavailable, falling back to rule-based only.",
            )

        # Truncate for performance (first 5000 chars is enough for ML)
        analysis_content = content[:5000] if len(content) > 5000 else content

        loop = asyncio.get_event_loop()

        ner_result = await loop.run_in_executor(
            None, self._run_ner, analysis_content
        )
        classification_result = await loop.run_in_executor(
            None, self._run_classification, analysis_content
        )

        # Merge results
        entities = ner_result["entities"]
        ner_confidence = ner_result["confidence"]
        clf_label = classification_result["label"]
        clf_confidence = classification_result["confidence"]

        # Combined ML confidence (NER better for specific PII, classifier for context)
        if entities:
            ml_confidence = (ner_confidence * 0.6) + (clf_confidence * 0.4)
        else:
            ml_confidence = clf_confidence

        ml_confidence = min(ml_confidence, 1.0)

        # Determine final label
        if ml_confidence >= 0.8:
            predicted_label = SensitivityLabel.RESTRICTED
        elif ml_confidence >= 0.6:
            predicted_label = SensitivityLabel.CONFIDENTIAL
        elif ml_confidence >= 0.3:
            predicted_label = SensitivityLabel.INTERNAL
        else:
            predicted_label = SensitivityLabel.PUBLIC

        context_flags = []
        if metadata:
            if metadata.get("filename", "").endswith((".test", ".spec", ".example")):
                context_flags.append("test_file")
            if metadata.get("source") == "documentation":
                context_flags.append("documentation_context")

        explanation = self._build_explanation(
            entities, clf_label, clf_confidence, ml_confidence
        )

        processing_time = (time.time() - start_time) * 1000

        return MLClassificationResult(
            ml_confidence=ml_confidence,
            predicted_label=predicted_label,
            entities_detected=entities,
            context_flags=context_flags,
            is_false_positive=False,
            processing_time_ms=processing_time,
            explanation=explanation,
        )

    def _run_ner(self, content: str) -> Dict:
        """Run spaCy NER. Returns entities with context windows."""
        if self._nlp is None:
            return {"entities": [], "confidence": 0.0}

        doc = self._nlp(content)
        entities = []
        max_weight = 0.0

        for ent in doc.ents:
            ent_type = ent.label_
            weight = PII_ENTITY_WEIGHTS.get(ent_type, 0.05)

            start = max(0, ent.start_char - 30)
            end = min(len(content), ent.end_char + 30)
            context_window = content[start:end]

            entities.append({
                "text": ent.text,
                "type": ent_type,
                "weight": weight,
                "start": ent.start_char,
                "end": ent.end_char,
                "context": context_window,
            })

            if weight > max_weight:
                max_weight = weight

        density_factor = min(len(entities) / 3.0, 1.5)
        ner_confidence = min(max_weight * density_factor, 1.0)

        return {"entities": entities, "confidence": ner_confidence}

    def _run_classification(self, content: str) -> Dict:
        """Run TF-IDF + SGD classifier."""
        if self._vectorizer is None or self._classifier is None:
            return {
                "label": SensitivityLabel.PUBLIC,
                "confidence": 0.0,
                "probabilities": {},
            }

        try:
            X = self._vectorizer.transform([content])
            predicted_label = self._classifier.predict(X)[0]

            probabilities = {}
            try:
                proba = self._classifier.predict_proba(X)[0]
                classes = self._classifier.classes_
                probabilities = {
                    cls: round(float(prob), 4)
                    for cls, prob in zip(classes, proba)
                }
            except AttributeError:
                probabilities = {predicted_label: 0.8}

            confidence = probabilities.get(predicted_label, 0.5)

            label_to_score = {
                SensitivityLabel.PUBLIC: confidence * 0.1,
                SensitivityLabel.INTERNAL: confidence * 0.4,
                SensitivityLabel.CONFIDENTIAL: confidence * 0.7,
                SensitivityLabel.RESTRICTED: confidence * 0.95,
            }

            return {
                "label": predicted_label,
                "confidence": label_to_score.get(predicted_label, 0.0),
                "probabilities": probabilities,
            }

        except Exception as e:
            logger.error("Classification failed", error=str(e))
            return {
                "label": SensitivityLabel.PUBLIC,
                "confidence": 0.0,
                "probabilities": {},
            }

    def _build_explanation(self, entities, clf_label, clf_confidence, combined) -> str:
        parts = []
        if entities:
            types = list(set(e["type"] for e in entities))
            parts.append(f"Detected entities: {', '.join(types)}")
        parts.append(f"Document classifier: {clf_label} ({clf_confidence:.0%})")
        parts.append(f"Combined ML score: {combined:.2f}")
        return " | ".join(parts)

    async def retrain(self, training_data: List[Tuple[str, str]]) -> Dict:
        """Retrain classifier with new labeled data (admin API)."""
        if not training_data:
            return {"error": "No training data provided"}

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._retrain_sync, training_data)

    def _retrain_sync(self, training_data: List[Tuple[str, str]]) -> Dict:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import SGDClassifier
        from sklearn.model_selection import cross_val_score

        texts = [t[0] for t in training_data]
        labels = [t[1] for t in training_data]

        vectorizer = TfidfVectorizer(
            max_features=10000,
            ngram_range=(1, 3),
            stop_words="english",
            sublinear_tf=True,
            min_df=1,
        )

        classifier = SGDClassifier(
            loss="modified_huber",
            alpha=0.0001,
            max_iter=1000,
            random_state=42,
            class_weight="balanced",
        )

        X = vectorizer.fit_transform(texts)
        scores = cross_val_score(classifier, X, labels, cv=min(5, len(texts)))
        classifier.fit(X, labels)

        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        with open(TFIDF_PATH, "wb") as f:
            pickle.dump(vectorizer, f)
        with open(CUSTOM_MODEL_PATH, "wb") as f:
            pickle.dump(classifier, f)

        self._vectorizer = vectorizer
        self._classifier = classifier

        logger.info("Classifier retrained", samples=len(training_data),
                    cv_accuracy=round(float(np.mean(scores)), 4))

        return {
            "samples": len(training_data),
            "cv_accuracy": round(float(np.mean(scores)), 4),
            "cv_std": round(float(np.std(scores)), 4),
            "labels_distribution": {
                label: labels.count(label) for label in set(labels)
            },
        }


def get_ml_service() -> MLClassificationService:
    """Get the singleton ML classification service instance."""
    return MLClassificationService()
