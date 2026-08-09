import sys
import threading
import logging
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ServerEndpoint

from honeypot.config import FTP_HOST, FTP_PORT, DASHBOARD_HOST, DASHBOARD_PORT
from honeypot.ftp_server import FTPHoneypotFactory
from dashboard.app import app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AegisFTP")


def start_flask_dashboard():
    logger.info(f"Starting Flask Dashboard on http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False, use_reloader=False)


def main():
    logger.info("==================================================")
    logger.info("     AegisFTP - High Interaction FTP Honeypot     ")
    logger.info("==================================================")

    # Start Flask Web Dashboard thread
    dashboard_thread = threading.Thread(target=start_flask_dashboard, daemon=True)
    dashboard_thread.start()

    # Start Twisted FTP Honeypot server
    logger.info(f"Starting Twisted FTP Server on {FTP_HOST}:{FTP_PORT}")
    endpoint = TCP4ServerEndpoint(reactor, FTP_PORT, interface=FTP_HOST)
    factory = FTPHoneypotFactory()
    
    endpoint.listen(factory)
    
    logger.info("FTP Honeypot is LIVE and waiting for connections...")
    
    try:
        reactor.run()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutting down FTP Honeypot server...")
        sys.exit(0)


if __name__ == "__main__":
    main()
