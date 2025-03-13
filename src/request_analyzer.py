from urllib.parse import urlparse, parse_qs
import json

class RequestAnalyzer:
    """Simple request analyzer that uses LLM detector."""
    
    def __init__(self, llm_detector, logger):
        """Initialize the request analyzer."""
        self.llm_detector = llm_detector
        self.logger = logger
    
    def parse_request(self, request_handler):
        """Parse an HTTP request into analyzable components."""
        components = {}
        
        # Parse URL
        parsed_url = urlparse(request_handler.path)
        components['path'] = parsed_url.path
        
        # Parse query parameters
        query_params = parse_qs(parsed_url.query)
        components['query_params'] = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}
        
        # Parse headers (excluding common ones to reduce noise)
        headers = {}
        for k, v in request_handler.headers.items():
            if k.lower() not in ['user-agent', 'accept', 'accept-encoding', 'connection']:
                headers[k.lower()] = v
        components['headers'] = headers
        
        # Parse body if present
        content_length = int(request_handler.headers.get('Content-Length', 0))
        if content_length > 0:
            body = request_handler.rfile.read(content_length).decode('utf-8', errors='ignore')
            components['body'] = body
            
            # For debugging
            self.logger.debug(f"Request body: {body[:100]}...")
            
            # Reset file pointer for later reading
            request_handler._body = body.encode('utf-8')
        
        # Add client IP
        components['client_ip'] = request_handler.client_address[0]
        
        return components
    
    def analyze_request(self, request_data):
        """
        Analyze a request using the LLM detector.
        
        Args:
            request_data: Dictionary containing request components
            
        Returns:
            Tuple of (is_allowed, reason)
        """
        # Log request for analysis
        self.logger.info(f"Analyzing request to {request_data.get('path', 'unknown path')}")
        
        # Use LLM to detect anomalies
        is_anomalous, explanation = self.llm_detector.analyze_request(request_data)
        
        if is_anomalous:
            return False, f"Potential security threat: {explanation}"
        else:
            return True, "Request allowed"
