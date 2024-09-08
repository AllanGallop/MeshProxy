import asyncio
import json
import meshtastic
import sys
import time
import sqlite3
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from google.protobuf.json_format import MessageToJson

# ==================
# Global Variables
# ==================
# These values should be set in the config.json file. Default values provided here.
LOCAL_HOST = '127.0.0.1'       # Local interface to bind to
LOCAL_PORT = 4403              # Local port to listen on
REMOTE_HOST = '192.168.1.5'    # Remote host to forward traffic to
REMOTE_PORT = 4403             # Remote port to forward traffic to
LOG_LEVEL = 'INFO'             # Logging level
RATE_LIMIT_MESSAGES = 5        # Max messages allowed per node in RATE_LIMIT_TIMEFRAME
RATE_LIMIT_TIMEFRAME = 60      # Timeframe in seconds for rate limiting
WHITELIST = set()              # Set of whitelisted node IDs
BLACKLIST = set()              # Set of blacklisted node IDs
BROADCAST_ADDR = 4294967295    # Broadcast address (default 0xFFFFFF)

# ==================
# Logger Setup
# ==================
def setup_logging():
    """Sets up the logging system, including rotating file handler."""
    global logger
    logger = logging.getLogger('MeshProxy')

    # Mapping between config LOG_LEVEL and actual logging levels
    log_levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    logger.setLevel(log_levels.get(LOG_LEVEL, logging.INFO))

    # Configure a rotating log handler
    handler = RotatingFileHandler('logs/meshproxy.log', maxBytes=1000000, backupCount=3)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    logger.info("Logging initialized")

# ==================
# Database Setup
# ==================
def setup_database():
    """Sets up the SQLite database for storing rate-limiting information."""
    global conn, c
    try:
        print("Configuring Database")
        conn = sqlite3.connect('meshproxy.db')
        c = conn.cursor()
        # Create table for rate limiting if it doesn't exist
        c.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
            node_id TEXT PRIMARY KEY,
            message_count INTEGER DEFAULT 0,
            last_message_time INTEGER DEFAULT 0,
            blocked_until INTEGER DEFAULT 0
            );
        ''')
        conn.commit()
        # Clear previous entries
        c.execute('''DELETE FROM rate_limits WHERE 1=1;''')
        conn.commit()
    except Exception as e:
        logger.error(f"Error: Unable to connect to database - {e}")
        sys.exit(1)

# ==================
# Configuration Loader
# ==================
def load_config():
    """Loads configuration from config.json."""
    global LOG_LEVEL, LOCAL_HOST, LOCAL_PORT, REMOTE_HOST, REMOTE_PORT, BROADCAST_ADDR, RATE_LIMIT_MESSAGES, RATE_LIMIT_TIMEFRAME
    config_file = Path('config/config.json')

    if config_file.is_file():
        print("Loading configuration from config.json.")
        with open(config_file) as f:
            config = json.load(f)

        # Override defaults with values from the config file
        LOG_LEVEL = config.get('LOG_LEVEL', LOG_LEVEL)
        LOCAL_HOST = config.get('LOCAL_HOST', LOCAL_HOST)
        LOCAL_PORT = config.get('LOCAL_PORT', LOCAL_PORT)
        REMOTE_HOST = config.get('REMOTE_HOST', REMOTE_HOST)
        REMOTE_PORT = config.get('REMOTE_PORT', REMOTE_PORT)
        RATE_LIMIT_MESSAGES = config.get('RATE_LIMIT_MESSAGES', RATE_LIMIT_MESSAGES)
        RATE_LIMIT_TIMEFRAME = config.get('RATE_LIMIT_TIMEFRAME', RATE_LIMIT_TIMEFRAME)
    else:
        print("Error: config.json not found!")
        sys.exit(1)

# ==================
# Whitelist & Blacklist Loader
# ==================
def load_whitelist_blacklist():
    """Loads whitelist and blacklist from their respective files."""
    global WHITELIST, BLACKLIST

    whitelist_file = Path('config/whitelist.txt')
    blacklist_file = Path('config/blacklist.txt')

    if whitelist_file.is_file():
        with open(whitelist_file) as f:
            WHITELIST = set(line.strip() for line in f if not line.startswith('#'))
        print(f"Loaded {len(WHITELIST)} whitelisted nodes.")

    if blacklist_file.is_file():
        with open(blacklist_file) as f:
            BLACKLIST = set(line.strip() for line in f if not line.startswith('#'))
        print(f"Loaded {len(BLACKLIST)} blacklisted nodes.")

# ==================
# Utility Functions
# ==================
def node_id_to_int(node_id):
    """Converts node ID string to integer."""
    if node_id.startswith('!'):
        node_id = node_id[1:]
    return int(node_id, 16)

def int_to_node_id(node_id_int):
    """Converts integer node ID back to string."""
    hex_str = f"{node_id_int:08x}"
    return f"!{hex_str}"

def check_rate_limit(node_id):
    """Checks whether a node has exceeded its rate limit."""
    now = int(time.time())
    c.execute("SELECT message_count, last_message_time FROM rate_limits WHERE node_id = ?", (node_id,))
    result = c.fetchone()

    if result:
        message_count, last_message_time = result
        if now - last_message_time > RATE_LIMIT_TIMEFRAME:
            message_count = 0

        if message_count >= RATE_LIMIT_MESSAGES:
            return False

        c.execute("UPDATE rate_limits SET message_count = message_count + 1, last_message_time = ? WHERE node_id = ?",
                  (now, node_id))
    else:
        c.execute("INSERT INTO rate_limits (node_id, message_count, last_message_time) VALUES (?, 1, ?)",
                  (node_id, now))

    conn.commit()
    return True

def block_node(node_id):
    """Blocks a node by setting a 'blocked_until' timestamp."""
    block_until = int(time.time()) + (RATE_LIMIT_TIMEFRAME * 60)
    c.execute("UPDATE rate_limits SET blocked_until = ? WHERE node_id = ?", (block_until, node_id))
    conn.commit()

def is_node_blocked(node_id):
    """Checks if a node is currently blocked."""
    now = int(time.time())
    c.execute("SELECT blocked_until FROM rate_limits WHERE node_id = ?", (node_id,))
    result = c.fetchone()

    if result:
        blocked_until = result[0]
        if blocked_until > now:
            return True
        else:
            c.execute("UPDATE rate_limits SET blocked_until = 0 WHERE node_id = ?", (node_id,))
            conn.commit()

    return False

def decodeNodeId(data):
    """Decodes node ID from a received Meshtastic packet."""
    try:
        if data[0] == 0x94 and data[1] == 0xC3:
            data_len = (data[2] << 8 | data[3])
            if data_len <= 512:
                msg = meshtastic.protobuf.mesh_pb2.FromRadio()
                msg.ParseFromString(data[4:4 + data_len])
                msg_json = json.loads(MessageToJson(msg))
                if msg.WhichOneof('payload_variant') == 'packet':
                    if msg_json.get('packet') != BROADCAST_ADDR and msg_json.get('packet') != 0:
                        if msg_json['packet']['decoded']['portnum'] == 'TEXT_MESSAGE_APP':
                            packet = msg_json['packet']
                            return packet['from']
        return False
    except Exception as e:
        logger.error(f"Error decoding node ID: {e}")
        return False

# ==================
# Proxy Functions
# ==================
async def forward_data(reader, writer, direction):
    """Forwards data between client and remote host."""
    try:
        while True:
            data = await reader.read(512)
            if not data:
                break

            if direction == "remote_to_local":
                node_int = decodeNodeId(data)
                if node_int:
                    node_id = int_to_node_id(node_int)
                    logger.debug(f"Packet received from: {node_id}")

                    if node_id in WHITELIST:
                        pass
                    elif node_id in BLACKLIST:
                        logger.warning(f"Node {node_id} is blacklisted, dropping packet.")
                        break
                    elif is_node_blocked(node_int):
                        logger.warning(f"Node {node_id} is blocked, dropping packet.")
                        break
                    elif not check_rate_limit(node_int):
                        block_node(node_int)
                        logger.warning(f"Node {node_id} exceeded rate limit and is now blocked.")
                        break

            writer.write(data)
            await writer.drain()
    except asyncio.CancelledError:
        pass  # Task was cancelled
    except Exception as e:
        logger.error(f"Error forwarding data ({direction}): {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def handle_client(reader, writer):
    """Handles incoming client connections and forwards data to remote server."""
    try:
        client_ip, client_port = writer.get_extra_info('peername')
        logger.info(f"New connection from {client_ip}:{client_port}")

        # Connect to the remote server
        remote_reader, remote_writer = await asyncio.open_connection(REMOTE_HOST, REMOTE_PORT)

        # Create tasks to forward data in both directions
        client_to_remote = asyncio.create_task(forward_data(reader, remote_writer, "client_to_remote"))
        remote_to_client = asyncio.create_task(forward_data(remote_reader, writer, "remote_to_local"))

        # Wait for both tasks to complete
        await asyncio.gather(client_to_remote, remote_to_client)
    except Exception as e:
        logger.error(f"Error handling client: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

# ==================
# Proxy Server Startup
# ==================
async def start_proxy():
    """Starts the proxy server."""
    try:
        server = await asyncio.start_server(handle_client, LOCAL_HOST, LOCAL_PORT)
        addr = server.sockets[0].getsockname()
        logger.info(f"Proxy listening on {addr}")

        async with server:
            await server.serve_forever()
    except Exception as e:
        logger.error(f"Error starting proxy server: {e}")

# ==================
# Main Entry Point
# ==================
if __name__ == "__main__":
    try:
        print("=============== MeshProxy =============")
        print("https://github.com/AllanGallop/MeshProxy")
        print("========================================")

        # Load configuration
        load_config()

        # Setup logging
        setup_logging()

        # Load whitelist and blacklist
        load_whitelist_blacklist()

        # Setup database
        setup_database()

        # Start proxy server
        asyncio.run(start_proxy())
    except KeyboardInterrupt:
        print("Proxy server stopped.")
