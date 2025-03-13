# from src.waf_server import WAFServer
import time
import argparse

def main():
    """Run the WAF simulator."""
    # parser = argparse.ArgumentParser(description='WAF Simulator')
    # parser.add_argument('--host', default='127.0.0.1', help='Host to bind the WAF server')
    # parser.add_argument('--port', type=int, default=8080, help='Port to bind the WAF server')
    # parser.add_argument('--target', required=True, help='Target URL to forward requests to')
    # parser.add_argument('--config', help='Path to WAF configuration file')
    # args = parser.parse_args()
    
    # waf_server = WAFServer(
    #     host=args.host,
    #     port=args.port,
    #     target_url=args.target,
    #     config_file=args.config
    # )
    
    try:
        # server_thread = waf_server.start()
        print(f"WAF server started..")
        # print(f"Forwarding requests to {args.target}")
        print("Press Ctrl+C to stop")
        
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\nStopping WAF server...")
        # waf_server.stop()
        print("WAF server stopped")

if __name__ == "__main__":
    main()
