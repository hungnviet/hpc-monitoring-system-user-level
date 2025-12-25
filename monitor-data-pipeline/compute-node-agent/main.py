import json
import logging
import signal
import sys
import time
from pathlib import Path
from threading import Thread, Event
from typing import Optional, Dict, Any

import etcd3

sys.path.insert(0, str(Path(__file__).parent / "collector"))
from main import VirtualSensor

sys.path.insert(0, str(Path(__file__).parent / "client"))
from main import MetricsStreamClient

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ComputeNodeAgent:
    def __init__(self, config_path: str = "infra.json"):
        self.config_path = config_path
        self.node_id: Optional[str] = None
        self.etcd_endpoint: Optional[str] = None

        self.etcd_client: Optional[etcd3.Etcd3Client] = None
        self.grpc_client: Optional[MetricsStreamClient] = None
        self.sensor: Optional[VirtualSensor] = None

        self.collection_window: float = 5.0  
        self.heartbeat_interval: float = 10.0 

        self.stop_event = Event()
        self.heartbeat_thread: Optional[Thread] = None
        self.status_watch_thread: Optional[Thread] = None
        self.collection_enabled = Event()

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, initiating shutdown")
        self.shutdown()

    def _load_config(self) -> bool:
        try:
            config_file = Path(__file__).parent / self.config_path
            logger.info(f"Loading configuration from {config_file}")

            with open(config_file, 'r') as f:
                config = json.load(f)

            self.node_id = config.get("node_id")
            self.etcd_endpoint = config.get("etcd_endpoint")  

            if not self.node_id or not self.etcd_endpoint:
                return False

            logger.info(f"Configuration loaded: node_id={self.node_id}, etcd_endpoint={self.etcd_endpoint}")
            return True

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return False

    def _connect_etcd(self, max_retries: int = 3) -> bool:
        endpoint = self.etcd_endpoint.replace("http://", "").replace("https://", "")
        parts = endpoint.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 2379

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Attempting to connect to etcd at {host}:{port} (attempt {attempt}/{max_retries})")

                self.etcd_client = etcd3.client(host=host, port=port)

                # Test connection
                self.etcd_client.status()

                logger.info(f"Successfully connected to etcd at {host}:{port}")
                return True

            except Exception as e:
                logger.error(f"Failed to connect to etcd (attempt {attempt}/{max_retries}): {e}")
                if attempt < max_retries:
                    sleep_time = min(2 ** attempt, 10)
                    logger.info(f"Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)
                else:
                    logger.error("Max retries reached. Could not connect to etcd.")
                    return False

        return False

    def _get_config_from_etcd(self, key: str, default: Any = None) -> Any:
        try:
            value, _ = self.etcd_client.get(key)
            if value:
                return value.decode('utf-8')
            return default
        except Exception as e:
            logger.warning(f"Failed to get config key '{key}': {e}")
            return default

    def _get_grpc_address(self) -> Optional[str]:
        key = f"/config/compute_node/{self.node_id}/target_collect_agent"
        address = self._get_config_from_etcd(key)

        if address:
            logger.info(f"Retrieved gRPC server address from etcd: {address}")
        else:
            logger.error(f"gRPC server address not found in etcd key: {key}")

        return address

    def _load_collection_config(self):
        window_key = f"/config/compute_node/{self.node_id}/window"
        window_str = self._get_config_from_etcd(window_key, str(self.collection_window))
        try:
            self.collection_window = float(window_str)
            logger.info(f"Collection window: {self.collection_window}s")
        except ValueError:
            logger.warning(f"Invalid window value '{window_str}', using default: {self.collection_window}s")

        heartbeat_key = f"/config/compute_node/{self.node_id}/heartbeat_interval"
        heartbeat_str = self._get_config_from_etcd(heartbeat_key, str(self.heartbeat_interval))
        try:
            self.heartbeat_interval = float(heartbeat_str)
            logger.info(f"Heartbeat interval: {self.heartbeat_interval}s")
        except ValueError:
            logger.warning(f"Invalid heartbeat value '{heartbeat_str}', using default: {self.heartbeat_interval}s")

    def _heartbeat_loop(self):
        heartbeat_key = f"/nodes/{self.node_id}/heartbeat"
        logger.info(f"Starting heartbeat loop with interval {self.heartbeat_interval}s")

        while not self.stop_event.is_set():
            try:
                heartbeat_data = {
                    "timestamp": int(time.time()),
                    "status": "alive",
                    "collection_active": self.collection_enabled.is_set()
                }

                self.etcd_client.put(heartbeat_key, json.dumps(heartbeat_data))
                logger.debug(f"Sent heartbeat: {heartbeat_data}")

            except Exception as e:
                logger.error(f"Failed to send heartbeat: {e}")

            # Sleep with stop event check
            self.stop_event.wait(self.heartbeat_interval)

        logger.info("Heartbeat loop stopped")

    def _watch_status_loop(self):
        status_key = f"/config/compute_node/{self.node_id}/status"
        logger.info(f"Watching status key: {status_key}")

        status = self._get_config_from_etcd(status_key, "stopped")
        if status == "running":
            self.collection_enabled.set()
            logger.info("Initial status: collection ENABLED")
        else:
            self.collection_enabled.clear()
            logger.info("Initial status: collection DISABLED")

        events_iterator, cancel = self.etcd_client.watch(status_key)

        try:
            for event in events_iterator:
                if self.stop_event.is_set():
                    break

                if isinstance(event, etcd3.events.PutEvent):
                    new_status = event.value.decode('utf-8') if event.value else ""
                    logger.info(f"Status changed to: {new_status}")

                    if new_status == "running":
                        self.collection_enabled.set()
                        logger.info("Collection ENABLED")
                    else:
                        self.collection_enabled.clear()
                        logger.info("Collection DISABLED")

        except Exception as e:
            logger.error(f"Error in status watch loop: {e}")
        finally:
            cancel()

    def _collection_loop(self):
        logger.info("Starting collection loop")

        while not self.stop_event.is_set():
            if not self.collection_enabled.is_set():
                self.collection_enabled.wait(timeout=1)
                continue

            try:
                start_time = time.time()
                metrics_data = self.sensor.collect(self.collection_window)

                if self.grpc_client:
                    success = self.grpc_client.send_metrics(
                        data=metrics_data,
                        node_id=self.node_id,
                        collection_window=self.collection_window
                    )

                    if success:
                        logger.info("Metrics sent successfully")
                    else:
                        logger.warning("Failed to send metrics")

            except Exception as e:
                logger.error(f"Error in collection loop: {e}", exc_info=True)
                time.sleep(1)

    def run(self):

        logger.info("=" * 60)
        logger.info("Starting Compute Node Agent")
        logger.info("=" * 60)

        if not self._load_config():
            logger.error("Failed to load configuration, exiting")
            return

        if not self._connect_etcd():
            logger.error("Failed to connect to etcd, exiting")
            return

        self._load_collection_config()

        grpc_address = self._get_grpc_address()
        if not grpc_address:
            logger.error("Failed to get gRPC server address, exiting")
            return

        try:
            logger.info("Initializing VirtualSensor...")
            self.sensor = VirtualSensor(
                ram_sample_interval_s=1.0,
                max_workers=2
            )
            logger.info("VirtualSensor initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize VirtualSensor: {e}")
            return

        try:
            logger.info(f"Initializing gRPC client to {grpc_address}...")
            self.grpc_client = MetricsStreamClient(
                server_address=grpc_address,
                max_retries=3
            )
            logger.info("gRPC client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize gRPC client: {e}")
            return

        logger.info("Starting background threads...")

        self.heartbeat_thread = Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

        self.status_watch_thread = Thread(target=self._watch_status_loop, daemon=True)
        self.status_watch_thread.start()

        logger.info("Background threads started")

        try:
            self._collection_loop()
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        except Exception as e:
            logger.error(f"Fatal error in main loop: {e}", exc_info=True)
        finally:
            self.shutdown()

    def shutdown(self):
        if self.stop_event.is_set():
            return  

        logger.info("=" * 60)
        logger.info("Shutting down Compute Node Agent")
        logger.info("=" * 60)

        self.stop_event.set()
        self.collection_enabled.clear()

        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            logger.info("Waiting for heartbeat thread to finish...")
            self.heartbeat_thread.join(timeout=5)

        if self.status_watch_thread and self.status_watch_thread.is_alive():
            logger.info("Waiting for status watch thread to finish...")
            self.status_watch_thread.join(timeout=5)

        if self.grpc_client:
            logger.info("Closing gRPC client...")
            self.grpc_client.close()

        if self.sensor:
            logger.info("Closing VirtualSensor...")
            self.sensor.close()

        if self.etcd_client:
            logger.info("Closing etcd client...")
            self.etcd_client = None

        logger.info("Shutdown complete")


def main():
    agent = ComputeNodeAgent()
    agent.run()


if __name__ == "__main__":
    main()
