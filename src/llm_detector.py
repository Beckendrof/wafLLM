import requests
import json
import logging
import re

class LLMDetector:
    """Simple LLM-based detector for WAF."""
    
    def __init__(self, logger):
        """Initialize the LLM detector."""
        self.logger = logger
        # Default to local Ollama endpoint
        self.llm_api_url = "http://localhost:11434/api/generate"
        self.model_name = "llama3:8b"
        
    def analyze_request(self, request_data):
        """
        Analyze request for anomalies using LLM.
        
        Args:
            request_data: Dictionary containing request components
            
        Returns:
            Tuple of (is_anomalous, explanation)
        """
        # Create simple prompt with request data
        prompt = self._create_detection_prompt(request_data)
        
        # Get LLM response
        response = self._query_llm(prompt)
        
        # Parse response
        is_anomalous, explanation = self._parse_llm_response(response)
        
        # Log the detection result
        if is_anomalous:
            self.logger.warning(f"Anomaly detected: {explanation}")
        
        return is_anomalous, explanation
    
    def _create_detection_prompt(self, request_data):
        """Create a simple detection prompt from request data."""
        url_path = request_data.get('path', '')
        query_params = str(request_data.get('query_params', {}))
        headers = str(request_data.get('headers', {}))
        body = request_data.get('body', '')
        
        prompt = f"""As a security expert, analyze this web request for potential security threats:

URL Path: {url_path}
Query Parameters: {query_params}
Headers: {headers}
Body: {body}

Is this request potentially malicious? Consider common web attacks like SQL Injection, XSS, Command Injection, or Path Traversal.
Respond with:
RESULT: [MALICIOUS/BENIGN]
REASON: [Your explanation]
"""
        return prompt
    
    def _query_llm(self, prompt):
        """Send request to LLM API with proper error handling."""
        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "options": {
                    "num_ctx": 2048,       # Limit context window
                    "num_predict": 300,    # Similar to max_tokens
                    "temperature": 0.1
                },
                "stream": False
            }
            
            # Add timeout to avoid hanging
            response = requests.post(self.llm_api_url, json=payload, timeout=90)
            
            if response.status_code == 200:
                try:
                    return response.json().get('response', '')
                except json.JSONDecodeError:
                    # Try to extract just the first JSON object
                    import re
                    json_match = re.search(r'({.*?})', response.text, re.DOTALL)
                    if json_match:
                        data = json.loads(json_match.group(1))
                        return data.get('response', '')
                    return "Error parsing LLM response"
            else:
                self.logger.error(f"LLM API error: {response.status_code}")
                return "Error connecting to LLM API"
        
        except requests.exceptions.Timeout:
            self.logger.error("LLM API request timed out")
            return "Analysis timed out - allowing request by default"
            
        except Exception as e:
            self.logger.error(f"Error querying LLM: {str(e)}")
            return "Error processing request"

    
    def _parse_llm_response(self, response):
        """Parse LLM response to extract detection results."""
        # Default values
        is_anomalous = False
        explanation = "No clear explanation provided"
        
        # Check if response contains MALICIOUS
        if "RESULT: MALICIOUS" in response:
            is_anomalous = True
        
        # Extract explanation
        reason_match = re.search(r"REASON: (.*?)($|\n)", response, re.DOTALL)
        if reason_match:
            explanation = reason_match.group(1).strip()
        
        return is_anomalous, explanation
