import json
import time
from etcd3 import Client as Etcd3Client
from pathlib import Path
from threading import Thread, Event
from typing import Optional, Any, Callable
from dataclasses import dataclass
from utils import get_logger


logger = get_logger(__name__)


@dataclass
class ComputeNodeConfig:
    node_id: str
    etcd_endpoint: str
    target_collect_agent: str = "localhost:50051"
    collection_window: float = 5.0
    heartbeat_interval: float = 10.0


class ConfigurationManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._config: Optional[ComputeNodeConfig] = None
            self._etcd_client: Optional[Etcd3Client] = None
            self._stop_event = Event()
            self._collection_enabled = Event()
            self._heartbeat_thread: Optional[Thread] = None
            self._status_watch_thread: Optional[Thread] = None
            self._status_callback: Optional[Callable[[bool], None]] = None
            self._initialized = True

    def load(self, infra_path: str = "infra.json") -> ComputeNodeConfig:
        logger.info(f"Loading configuration from {infra_path}")

        infra_file = Path(__file__).parent / infra_path
        with open(infra_file, 'r') as f:
            infra = json.load(f)

        node_id = infra.get("node_id")
        etcd_endpoint = infra.get("etcd_endpoint")

        if not node_id or not etcd_endpoint:
            raise ValueError("Missing node_id or etcd_endpoint in infra.json")

        self._connect_etcd(etcd_endpoint)

        self._config = ComputeNodeConfig(
            node_id=node_id,
            etcd_endpoint=etcd_endpoint
        )

        self._load_from_etcd()

        logger.info(f"Configuration loaded for node: {node_id}")
        return self._config

    def _connect_etcd(self, endpoint: str, max_retries: int = 3):
        endpoint = endpoint.replace("http://", "").replace("https://", "")
        parts = endpoint.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 2379

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Connecting to etcd at {host}:{port} (attempt {attempt}/{max_retries})")
                self._etcd_client = Etcd3Client(host=host, port=port)
                self._etcd_client.status()
                logger.info("Connected to etcd successfully")
                return
            except Exception as e:
                logger.error(f"Failed to connect to etcd (attempt {attempt}/{max_retries}): {e}")
                if attempt < max_retries:
                    sleep_time = min(2 ** attempt, 10)
                    logger.info(f"Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)
                else:
                    raise ConnectionError("Max retries reached. Could not connect to etcd.")

    def _load_from_etcd(self):
        prefix = f"/config/compute_node/{self._config.node_id}"

        target = self._get_etcd_value(f"{prefix}/target_collect_agent")
        if target:
            self._config.target_collect_agent = target
            logger.info(f"Target collect agent: {target}")
        else:
            logger.warning(f"target_collect_agent not found, using default: {self._config.target_collect_agent}")

        window = self._get_etcd_value(f"{prefix}/window")
        if window:
            try:
                self._config.collection_window = float(window)
                logger.info(f"Collection window: {self._config.collection_window}s")
            except ValueError:
                logger.warning(f"Invalid window value '{window}', using default")

        heartbeat = self._get_etcd_value(f"{prefix}/heartbeat_interval")
        if heartbeat:
            try:
                self._config.heartbeat_interval = float(heartbeat)
                logger.info(f"Heartbeat interval: {self._config.heartbeat_interval}s")
            except ValueError:
                logger.warning(f"Invalid heartbeat value '{heartbeat}', using default")

    def _get_etcd_value(self, key: str) -> Optional[str]:
        try:
            # etcd3-py uses range() method instead of get()
            result = self._etcd_client.range(key)
            if result.kvs and len(result.kvs) > 0:
                return result.kvs[0].value.decode('utf-8')
        except Exception as e:
            logger.warning(f"Failed to get key '{key}': {e}")
        return None

    @property
    def config(self) -> ComputeNodeConfig:
        if self._config is None:
            raise RuntimeError("Configuration not loaded. Call load() first.")
        return self._config

    @property
    def collection_enabled(self) -> Event:
        return self._collection_enabled

    @property
    def stop_event(self) -> Event:
        return self._stop_event

    def start_background_tasks(self, status_callback: Optional[Callable[[bool], None]] = None):
        self._status_callback = status_callback

        self._heartbeat_thread = Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        self._status_watch_thread = Thread(target=self._watch_status_loop, daemon=True)
        self._status_watch_thread.start()

        logger.info("Background tasks started (heartbeat and status watch)")

    def _heartbeat_loop(self):
        heartbeat_key = f"/nodes/{self._config.node_id}/heartbeat"
        logger.info(f"Starting heartbeat loop with interval {self._config.heartbeat_interval}s")

        while not self._stop_event.is_set():
            try:
                heartbeat_data = {
                    "timestamp": int(time.time()),
                    "status": "alive",
                    "collection_active": self._collection_enabled.is_set()
                }
                self._etcd_client.put(heartbeat_key, json.dumps(heartbeat_data))
                logger.debug(f"Sent heartbeat: {heartbeat_data}")
            except Exception as e:
                logger.error(f"Failed to send heartbeat: {e}")

            self._stop_event.wait(self._config.heartbeat_interval)

        logger.info("Heartbeat loop stopped")

    def _watch_status_loop(self):
        status_key = f"/config/compute_node/{self._config.node_id}/status"
        logger.info(f"Watching status key: {status_key}")

        status = self._get_etcd_value(status_key) or "stopped"
        if status == "running":
            self._collection_enabled.set()
            logger.info("Initial status: collection ENABLED")
        else:
            self._collection_enabled.clear()
            logger.info("Initial status: collection DISABLED")

        if self._status_callback:
            self._status_callback(self._collection_enabled.is_set())

        events_iterator, cancel = self._etcd_client.watch(status_key)

        try:
            for event in events_iterator:
                if self._stop_event.is_set():
                    break

                if hasattr(event, 'value'):
                    new_status = event.value.decode('utf-8') if event.value else ""
                    logger.info(f"Status changed to: {new_status}")

                    if new_status == "running":
                        self._collection_enabled.set()
                        logger.info("Collection ENABLED")
                    else:
                        self._collection_enabled.clear()
                        logger.info("Collection DISABLED")

                    if self._status_callback:
                        self._status_callback(self._collection_enabled.is_set())

        except Exception as e:
            logger.error(f"Error in status watch loop: {e}")
        finally:
            cancel()

    def shutdown(self):
        logger.info("Shutting down configuration manager...")
        self._stop_event.set()
        self._collection_enabled.clear()

        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            logger.info("Waiting for heartbeat thread to finish...")
            self._heartbeat_thread.join(timeout=5)

        if self._status_watch_thread and self._status_watch_thread.is_alive():
            logger.info("Waiting for status watch thread to finish...")
            self._status_watch_thread.join(timeout=5)

        if self._etcd_client:
            self._etcd_client = None

        logger.info("Configuration manager shutdown complete")

    def reload(self):
        if self._config:
            self._load_from_etcd()
            logger.info("Configuration reloaded from etcd")
