from src.waf_server import WAFServer
import argparse
import threading
import time

def main():
    """Run the basic RAAD-LLM WAF."""
    parser = argparse.ArgumentParser(description='Basic LLM-based WAF')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind the WAF server')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind the WAF server')
    parser.add_argument('--target', required=True, help='Target URL to forward requests to')
    args = parser.parse_args()
    
    # Create and start the WAF server
    server_address = (args.host, args.port)
    waf_server = WAFServer(server_address, args.target)
    
    try:
        # Run the server in a separate thread
        server_thread = threading.Thread(target=waf_server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        print(f"LLM-based WAF server started on {args.host}:{args.port}")
        print(f"Forwarding requests to {args.target}")
        print("Press Ctrl+C to stop")
        
        # Keep the main thread running
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\nStopping WAF server...")
        waf_server.shutdown()
        print("WAF server stopped")

if __name__ == "__main__":
    main()
