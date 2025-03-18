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
        print(response)
        
        # Parse response
        is_anomalous, explanation = self._parse_llm_response(response)
        
        # Log the detection result
        if is_anomalous:
            self.logger.warning(f"Anomaly detected: {explanation}")
        
        return is_anomalous, explanation
    
    def _create_detection_prompt(self, request_data):
        """Create a simple detection prompt from request data."""
        request = self._parse_request(str(request_data.get('body', '')))
        print(request)
        
        return f"""You are a WAF simulator analyzing a request.
REQUEST BODY: {request}

MALICIOUS: [YES/NO]
REASON: [5 words]
"""
    
    def _query_llm(self, prompt):
        """Send request to LLM API with proper error handling."""
        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "options": {
                    "num_ctx": 512,       # Limit context window
                    "num_predict": 50,    # Similar to max_tokens
                    "top_k": 1,           # Disable top-k sampling
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
        if "**Malicious:** YES" in response:
            is_anomalous = True
        
        # Extract explanation
        reason_match = re.search(r"REASON: (.*?)($|\n)", response, re.DOTALL)
        if reason_match:
            explanation = reason_match.group(1).strip()
        
        return is_anomalous, explanation
    
    def _parse_multipart_form(self, body_string):
        """Parse multipart form data into structured dictionary"""
        if not self._is_multipart_form(body_string):
            return body_string
        
        # Normalize line endings to \n for consistent processing
        body_string = body_string.replace('\r\n', '\n')
        
        # Extract boundary from first line
        first_line_end = body_string.find('\n')
        boundary = body_string[:first_line_end].strip()
        
        # Split the body by boundary
        parts = body_string.split(boundary)
        
        # First part is empty, last part is the end boundary marker
        parts = [p for p in parts if p and '--\n' not in p]
        if len(parts) > 0 and parts[0] == '':
            parts = parts[1:]
        
        parsed_data = {}
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
            
            # Split part into lines
            part_lines = part.split('\n')
            
            # Extract field name and filename if present
            content_disp_line = next((line for line in part_lines if 'Content-Disposition:' in line), '')
            
            name_match = re.search(r'name="([^"]+)"', content_disp_line)
            if not name_match:
                continue
                    
            field_name = name_match.group(1)
            
            # Check if this is a file upload
            filename_match = re.search(r'filename="([^"]+)"', content_disp_line)
            
            # Find content type if present
            content_type_line = next((line for line in part_lines if 'Content-Type:' in line), '')
            content_type_match = re.search(r'Content-Type: (.+)', content_type_line)
            content_type = content_type_match.group(1).strip() if content_type_match else ''
            
            # Find the empty line that separates headers from content
            content = ""
            content_started = False
            for i, line in enumerate(part_lines):
                if content_started:
                    content += line + "\n"
                elif line.strip() == '':
                    content_started = True
            
            content = content.strip()
            
            if filename_match:
                parsed_data[field_name] = {
                    'filename': filename_match.group(1),
                    'content_type': content_type,
                    # 'value': content
                }
            else:
                parsed_data[field_name] = content
        
        return parsed_data

    def _parse_request(self, body_string):
        """Parse form data and return as JSON"""
        try:
            result = self._parse_multipart_form(body_string)
            return json.dumps(result, indent=4)
        except Exception as e:
            return json.dumps({"error": str(e), "body": body_string})

    def _is_multipart_form(self, body_string):
        """Check if a body string appears to be multipart form data"""
        if not body_string or not isinstance(body_string, str):
            return False
        
        # Check if it starts with boundary delimiter (several hyphens)
        has_boundary = body_string.startswith('------')
        
        # Check for Content-Disposition which is always in multipart forms
        has_content_disposition = 'Content-Disposition: form-data;' in body_string
        
        return has_boundary and has_content_disposition