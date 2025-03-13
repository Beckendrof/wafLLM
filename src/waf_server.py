from http.server import HTTPServer
import logging
from .request_handler import WAFRequestHandler
from .llm_detector import LLMDetector
from .request_analyzer import RequestAnalyzer

class WAFServer(HTTPServer):
    def __init__(self, server_address, target_url=None):
        """Initialize the WAF server with LLM-based detection."""
        self.target_url = target_url
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Initialize LLM detector and request analyzer
        self.llm_detector = LLMDetector(self.logger)
        self.request_analyzer = RequestAnalyzer(self.llm_detector, self.logger)
        
        # Initialize HTTP server
        super().__init__(server_address, WAFRequestHandler)
        
        self.logger.info(f"WAF Server initialized with target URL: {target_url}")
    
    def _setup_logging(self):
        """Set up basic logging."""
        logger = logging.getLogger('waf_server')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
