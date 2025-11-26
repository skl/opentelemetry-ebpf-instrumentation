# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import os
import time
import logging
from datetime import datetime
from threading import Lock
from fastapi import FastAPI, HTTPException
import uvicorn
import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

app = FastAPI()

# Global variables
client = None
topic = "test/topic"
qos = 1
mu = Lock()
count = 0

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def wait_for_broker(broker_host, broker_port):
    """Wait for MQTT broker to be ready"""
    logger.info(f"Waiting for MQTT broker at {broker_host}:{broker_port}...")
    while True:
        try:
            test_client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id="pythonmqtt_publisher_test")
            test_client.connect(broker_host, broker_port, 5)
            test_client.disconnect()
            logger.info(f"Connected to MQTT broker at {broker_host}:{broker_port}")
            break
        except Exception as e:
            logger.info(f"Failed to connect, retrying in 2 seconds... Error: {e}")
            time.sleep(2)


def on_connect(client, userdata, flags, reason_code, properties):
    """Callback for when the client receives a CONNACK response from the server"""
    if reason_code.is_failure:
        logger.error(f"Failed to connect, reason code: {reason_code}")
    else:
        logger.info("Connected to MQTT broker")


def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    """Callback for when the client disconnects from the server"""
    if reason_code.is_failure:
        logger.warning(f"Unexpected disconnection: {reason_code}")


def setup_mqtt_client(broker_host, broker_port):
    """Set up and connect MQTT client"""
    global client
    
    client_id = f"pythonmqtt_publisher_{int(time.time())}"
    client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=client_id, clean_session=True)
    
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    
    client.connect(broker_host, broker_port, 60)
    client.loop_start()
    
    # Wait a bit for connection to establish
    time.sleep(1)
    
    return client


@app.get("/mqtt")
@app.post("/mqtt")
async def mqtt_publish():
    """Handle HTTP request to publish MQTT message"""
    global count, client
    
    mu.acquire()
    count += 1
    message_num = count
    mu.release()
    
    # Ensure client is connected
    if client is None or not client.is_connected():
        logger.warning("Client not connected, attempting to reconnect...")
        broker = os.getenv("MQTT_BROKER", "vernemq:1883")
        broker_host, broker_port = broker.split(":") if ":" in broker else (broker, 1883)
        broker_port = int(broker_port)
        try:
            client = setup_mqtt_client(broker_host, broker_port)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"MQTT connection error: {str(e)}")
    
    # Publish message
    payload = f"Hello from pythonmqtt! Message #{message_num}, Timestamp: {datetime.now().isoformat()}"
    logger.info(f"Publishing message #{message_num} to topic '{topic}' with QOS {qos}: {payload}")
    
    try:
        result = client.publish(topic, payload, qos)
        result.wait_for_publish(timeout=5)
        
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise HTTPException(status_code=500, detail=f"Publish error: {result.rc}")
        
        # Respond with the results
        response = {
            "message_number": message_num,
            "topic": topic,
            "qos": qos,
            "payload": payload,
            "published": True,
        }
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Publish error: {str(e)}")


if __name__ == "__main__":
    # Get configuration from environment
    broker = os.getenv("MQTT_BROKER", "vernemq:1883")
    broker_host, broker_port = broker.split(":") if ":" in broker else (broker, 1883)
    broker_port = int(broker_port)
    
    topic = os.getenv("MQTT_TOPIC", "test/topic")
    
    qos_str = os.getenv("MQTT_QOS", "1")
    try:
        qos = int(qos_str)
        if qos < 0 or qos > 2:
            qos = 1
    except ValueError:
        qos = 1
    
    # Wait for broker to be ready
    wait_for_broker(broker_host, broker_port)
    
    # Set up MQTT client
    setup_mqtt_client(broker_host, broker_port)
    
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)

