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


LOCAL_HOST = '127.0.0.1'
LOCAL_PORT = 4403
REMOTE_HOST = '192.168.1.242'
REMOTE_PORT = 4403
LOG_LEVEL = 'INFO'
RATE_LIMIT_MESSAGES = 5
RATE_LIMIT_TIMEFRAME = 60
WHITELIST = set()
BLACKLIST = set()
BROADCAST_ADDR = 4294967295 #0xFFFFFF

# Logger setup
def setup_logging():

    global logger
    logger = logging.getLogger('MeshProxy')
    log_levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    logger.setLevel(log_levels.get(LOG_LEVEL, logging.INFO))

    # Create a rotating file handler
    handler = RotatingFileHandler('logs/meshproxy.log', maxBytes=1000000, backupCount=3)
    
    # Create a formatter and set it for the handler
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)

    logger.info("Starting Logging")

def setup_database():
    global conn, c
    try:
            print("Configuring Database")
            conn = sqlite3.connect('meshproxy.db')
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS rate_limits (
                node_id TEXT PRIMARY KEY,
                message_count INTEGER DEFAULT 0,
                last_message_time INTEGER DEFAULT 0,
                blocked_until INTEGER DEFAULT 0
                );
            ''')
            conn.commit()
            c = conn.cursor()
            c.execute('''DELETE FROM rate_limits WHERE 1=1;''')
            conn.commit()
    except Exception as e:
        logger.error(f"Error: Unable to connect to database - {e}")
        sys.exit(1)

def load_config():
    global LOG_LEVEL, LOCAL_HOST, LOCAL_PORT, REMOTE_HOST, REMOTE_PORT, BROADCAST_ADDR, RATE_LIMIT_MESSAGES, RATE_LIMIT_TIMEFRAME
    configFile = Path('config/config.json')
    
    if configFile.is_file():
        print("config.json found.")
        with open('config/config.json') as f:
            config = json.load(f)

        # Apply values from config file if they exist
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

def load_whitelist_blacklist():
    global WHITELIST, BLACKLIST
    
    whitelist_file = Path('config/whitelist.txt')
    blacklist_file = Path('config/blacklist.txt')

    if whitelist_file.is_file():
        with open('config/whitelist.txt') as f:
            WHITELIST = set(line.strip() for line in f if not line.startswith('#'))
        print(f"Loaded {len(WHITELIST)} whitelisted nodes.")

    if blacklist_file.is_file():
        with open('config/blacklist.txt') as f:
            BLACKLIST = set(line.strip() for line in f if not line.startswith('#'))
        print(f"Loaded {len(BLACKLIST)} blacklisted nodes.")

def node_id_to_int(node_id):
    if node_id.startswith('!'):
        node_id = node_id[1:]
    
    return int(node_id, 16)

def int_to_node_id(node_id_int):
    hex_str = f"{node_id_int:08x}"
    return f"!{hex_str}"

def check_rate_limit(node_id):
    now = int(time.time())
    c.execute("SELECT message_count, last_message_time FROM rate_limits WHERE node_id = ?", (node_id,))
    result = c.fetchone()

    if result:
        message_count, last_message_time = result
        if now - last_message_time > 60:
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
    block_until = int(time.time()) + (RATE_LIMIT_TIMEFRAME* 60)
    c.execute("UPDATE rate_limits SET blocked_until = ? WHERE node_id = ?", (block_until, node_id))
    conn.commit()

def is_node_blocked(node_id):
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

    except:
        return False

async def forward_data(reader, writer, direction):
    try:
        while True:
            data = await reader.read(512)
            if not data:
                break
            
            if direction == "remote_to_local":
                node_int = decodeNodeId(data)
                node_id = int_to_node_id(node_int)
                if(node_int):
                    logger.debug(f"Packet heard from: {node_id}")
                    if node_id in WHITELIST:
                        pass
                    elif node_id in BLACKLIST:
                        logger.warning(f"Node {node_id} is blacklisted, packet dropped.")
                        break
                    elif is_node_blocked(node_int):
                        logger.warning(f"Node {node_id} is blocked, packet dropped.")
                        break
                    elif not check_rate_limit(node_int):
                        block_node(node_int)
                        logger.warning(f"Node {node_id} exceeded the rate limit and is now blocked.")
                        break
            
            writer.write(data)
            await writer.drain()
    except asyncio.CancelledError:
        pass  # Task was cancelled, clean up
    except Exception as e:
        logger.error(f"Error while forwarding data in {direction}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def handle_client(reader, writer):
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
    except asyncio.TimeoutError:
        logger.error("Connection timed out while trying to connect to remote server")
    except asyncio.CancelledError:
        pass  # Task was cancelled
    except Exception as e:
        logger.error(f"Error while handling client: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def start_proxy():
    try:
        server = await asyncio.start_server(handle_client, LOCAL_HOST, LOCAL_PORT)
        addr = server.sockets[0].getsockname()
        print(f'Proxy listening on {addr}')
        
        async with server:
            await server.serve_forever()
    except Exception as e:
        print(f"Error while starting the proxy server: {e}")

if __name__ == "__main__":
    try:
        print("=============== MeshProxy =============")
        print("https://github.com/AllanGallop/MeshProxy")
        print("========================================")
        
        # Load configuration
        load_config()

        # Setup Logging
        setup_logging()

        # Load whitelist and blacklist
        load_whitelist_blacklist()

        # Setup Database
        setup_database()
            
        asyncio.run(start_proxy())
    except KeyboardInterrupt:
        print("Proxy server stopped.")
