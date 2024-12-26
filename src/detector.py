import re
import json
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

@dataclass
class Detection:
    """Represents a detection result."""
    attack_type: str
    confidence: float
    payload: str
    mitigation: str

class LLMBasedWAF:
    """
    LLM-based Web Application Firewall for detecting various attack patterns.
    """
    
    def __init__(self, model_name: str = "microsoft/DialoGPT-medium"):
        """Initialize the WAF with a pre-trained model."""
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
        
        # Common attack patterns
        self.sql_patterns = [
            r"(\bselect\b.*\bfrom\b|\bunion\b.*\bselect\b)",
            r"(\bor\b\s+\d+\s*=\s*\d+|\band\b\s+\d+\s*=\s*\d+)",
            r"(\bdrop\b\s+\btable\b|\bdelete\b\s+\bfrom\b)",
            r"(\binsert\b\s+\binto\b|\bupdate\b.*\bset\b)"
        ]
        
        self.xss_patterns = [
            r"(<script.*?>.*?</script>|<img.*?onerror.*?>)",
            r"(javascript:|vbscript:|data:text/html)",
            r"(\bon\w+\s*=|<iframe.*?>)"
        ]
        
        self.rfi_patterns = [
            r"(http://|https://|ftp://|file://)",
            r"(\.\./.*\.\./|\.\.\\.*\.\.\\)",
            r"(php://|expect://|zip://)"
        ]
        
    def detect_sql_injection(self, payload: str) -> Optional[Detection]:
        """Detect SQL injection attempts."""
        payload_lower = payload.lower()
        
        for pattern in self.sql_patterns:
            if re.search(pattern, payload_lower, re.IGNORECASE):
                return Detection(
                    attack_type="SQL Injection",
                    confidence=0.9,
                    payload=payload,
                    mitigation="Use parameterized queries and input validation"
                )
        return None
        
    def detect_xss(self, payload: str) -> Optional[Detection]:
        """Detect Cross-Site Scripting attempts."""
        for pattern in self.xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return Detection(
                    attack_type="Cross-Site Scripting (XSS)",
                    confidence=0.85,
                    payload=payload,
                    mitigation="Sanitize user input and use Content Security Policy"
                )
        return None
        
    def detect_rfi(self, payload: str) -> Optional[Detection]:
        """Detect Remote File Inclusion attempts."""
        for pattern in self.rfi_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return Detection(
                    attack_type="Remote File Inclusion (RFI)",
                    confidence=0.8,
                    payload=payload,
                    mitigation="Validate file paths and disable remote file inclusion"
                )
        return None
        
    def llm_analyze(self, payload: str) -> float:
        """Use LLM to analyze suspicious patterns."""
        try:
            inputs = self.tokenizer(
                payload, 
                return_tensors="pt", 
                truncation=True, 
                max_length=512
            )
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
                malicious_score = probabilities[0][1].item()  # Assuming class 1 is malicious
                
            return malicious_score
        except Exception:
            return 0.0
            
    def analyze_request(self, payload: str) -> List[Detection]:
        """Analyze a request payload for various attack types."""
        detections = []
        
        # Rule-based detection
        sql_detection = self.detect_sql_injection(payload)
        if sql_detection:
            detections.append(sql_detection)
            
        xss_detection = self.detect_xss(payload)
        if xss_detection:
            detections.append(xss_detection)
            
        rfi_detection = self.detect_rfi(payload)
        if rfi_detection:
            detections.append(rfi_detection)
            
        # LLM-based analysis for unknown patterns
        llm_score = self.llm_analyze(payload)
        if llm_score > 0.7:
            detections.append(Detection(
                attack_type="Suspicious Pattern (LLM Detected)",
                confidence=llm_score,
                payload=payload,
                mitigation="Review request manually and implement appropriate filtering"
            ))
            
        return detections
        
    def is_malicious(self, payload: str, threshold: float = 0.5) -> bool:
        """Determine if a payload is malicious based on detection threshold."""
        detections = self.analyze_request(payload)
        if not detections:
            return False
            
        max_confidence = max(detection.confidence for detection in detections)
        return max_confidence >= threshold 