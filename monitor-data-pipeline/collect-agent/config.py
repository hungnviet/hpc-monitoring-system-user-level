import json
from etcd3 import Client as Etcd3Client
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from utils import get_logger


logger = get_logger(__name__)


@dataclass
class ThresholdRule:
    metric_name: str
    max_value: Optional[float] = None
    min_value: Optional[float] = None


@dataclass
class UserProcessorConfig:
    type: str
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectAgentConfig:
    collect_agent_id: str
    etcd_endpoint: str

    kafka_brokers: List[str] = field(default_factory=lambda: ["localhost:9092"])
    kafka_topic: str = "metrics"

    main_server_address: str = "localhost:50052"

    grpc_port: int = 50051
    grpc_max_workers: int = 10

    threshold_rules: List[ThresholdRule] = field(default_factory=list)
    user_processors: List[UserProcessorConfig] = field(default_factory=list)


class ConfigurationManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._config: Optional[CollectAgentConfig] = None
            self._etcd_client: Optional[Etcd3Client] = None
            self._initialized = True

    def load(self, infra_path: str = "infra.json") -> CollectAgentConfig:
        logger.info(f"Loading configuration from {infra_path}")

        infra_file = Path(__file__).parent / infra_path
        with open(infra_file, 'r') as f:
            infra = json.load(f)

        collect_agent_id = infra.get("collect_agent_id")
        etcd_endpoint = infra.get("etcd_endpoint")

        if not collect_agent_id or not etcd_endpoint:
            raise ValueError("Missing collect_agent_id or etcd_endpoint in infra.json")

        self._connect_etcd(etcd_endpoint)

        self._config = CollectAgentConfig(
            collect_agent_id=collect_agent_id,
            etcd_endpoint=etcd_endpoint
        )

        self._load_from_etcd()

        logger.info(f"Configuration loaded for agent: {collect_agent_id}")
        return self._config

    def _connect_etcd(self, endpoint: str):
        endpoint = endpoint.replace("http://", "").replace("https://", "")
        parts = endpoint.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 2379

        logger.info(f"Connecting to etcd at {host}:{port}")
        self._etcd_client = Etcd3Client(host=host, port=port)
        self._etcd_client.status()
        logger.info("Connected to etcd successfully")

    def _load_from_etcd(self):
        prefix = f"/config/collect_agent/{self._config.collect_agent_id}"

        kafka_brokers = self._get_etcd_value(f"{prefix}/kafka_brokers")
        if kafka_brokers:
            self._config.kafka_brokers = json.loads(kafka_brokers)

        kafka_topic = self._get_etcd_value(f"{prefix}/kafka_topic")
        if kafka_topic:
            self._config.kafka_topic = kafka_topic

        main_server = self._get_etcd_value(f"{prefix}/main_server_address")
        if main_server:
            self._config.main_server_address = main_server

        grpc_port = self._get_etcd_value(f"{prefix}/grpc_port")
        if grpc_port:
            self._config.grpc_port = int(grpc_port)

        threshold_rules = self._get_etcd_value(f"{prefix}/threshold_rules")
        if threshold_rules:
            rules_data = json.loads(threshold_rules)
            self._config.threshold_rules = [
                ThresholdRule(
                    metric_name=name,
                    max_value=rule.get("max"),
                    min_value=rule.get("min")
                )
                for name, rule in rules_data.items()
            ]

        user_processors = self._get_etcd_value(f"{prefix}/user_processors")
        if user_processors:
            processors_data = json.loads(user_processors)
            self._config.user_processors = [
                UserProcessorConfig(
                    type=proc.get("type"),
                    params=proc.get("params", {})
                )
                for proc in processors_data
            ]

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
    def config(self) -> CollectAgentConfig:
        if self._config is None:
            raise RuntimeError("Configuration not loaded. Call load() first.")
        return self._config

    def reload(self):
        if self._config:
            self._load_from_etcd()
            logger.info("Configuration reloaded from etcd")

