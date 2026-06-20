import re

class PIIRedactor:
    """
    Identifies and redacts Personally Identifiable Information (PII) from text.
    """
    def __init__(self):
        # Compiled patterns for high-precision redaction
        self.patterns = {
            "email": re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
            "credit_card": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'),
            "phone": re.compile(r'\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b'),
            "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            "ipv4": re.compile(r'\b(?!(?:0|10|127|169\.254|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1])))(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            "ipv6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
        }

    def redact(self, text, enabled=True):
        """
        Redacts PII from the provided text if enabled.
        """
        if not enabled or not text:
            return text
        
        redacted_text = str(text)
        
        for pii_type, pattern in self.patterns.items():
            redacted_text = pattern.sub(f"[REDACTED_{pii_type.upper()}]", redacted_text)
            
        return redacted_text

    def redact_dict(self, data, enabled=True):
        """
        Recursively redacts PII from dictionary values.
        """
        if not enabled:
            return data
            
        if isinstance(data, dict):
            return {k: self.redact_dict(v, enabled) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.redact_dict(item, enabled) for item in data]
        elif isinstance(data, str):
            return self.redact(data, enabled)
        else:
            return data

if __name__ == "__main__":
    redactor = PIIRedactor()
    test_str = "Contact me at john.doe@example.com or call 555-0199. My IP is 192.168.1.1."
    print("Original:", test_str)
    print("Redacted:", redactor.redact(test_str))
