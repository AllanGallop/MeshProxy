# MeshProxy

**MeshProxy** is a network proxy service that facilitates communication between Meshtastic devices and user applications. It serves as a middleware, offering advanced control features such as rate limiting, whitelisting, and blacklisting for managing device messaging interactions over the Meshtastic network.

<a name="usage"></a>
## Usage

### Docker

1. Clone this repository  
```git clone https://github.com/AllanGallop/MeshProxy.git```

2. [Configure](#configure)

3. Build  
```docker compose -f Docker/docker-compose.yaml up --build```

### Locally

1. Clone this repository  
```git clone https://github.com/AllanGallop/MeshProxy.git```

2. Install requirements  
```pip install --no-cache-dir --break-system-packages -r MeshProxy/requirements.txt```

2. [Configure](#configure)

3. Run  
```python MeshProxy/meshproxy.py```


<a name="configure"></a>
## Configure

### config.json

|  Key     | Default Value   | Notes |
| -------- | ------- | ----- |
| LOG_LEVEL| "INFO"  | Sets logging level (DEBUG, INFO, WARNING) |
| LOCAL_HOST | "0.0.0.0" | Proxy listening address |
| LOCAL_POST | 4403 | Proxy listening port |
| REMOTE_HOST | "192.168.1.5" | Host Address of your meshtastic node |
| REMOTE_HOST | 4403 | Host Port of your meshtastic node |
| RATE_LIMIT_MESSAGES | 5 | Amount of messages in timeframe |
| RATE_LIMIT_TIMEFRAME | 60 | Timeframe in seconds |

### Whitelist / Blacklist

Nodes can be white/black listed by entering the node id into the appropiate text files located in the config directory. Use `#` to comment lines out.



