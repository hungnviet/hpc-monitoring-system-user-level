import grpc
import time
import asyncio
from typing import Dict
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from proto import alerts_pb2, alerts_pb2_grpc
from utils import get_logger


logger = get_logger(__name__)


class AlertClient:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, server_address: str, collect_agent_id: str):
        if not hasattr(self, '_initialized'):
            self.server_address = server_address
            self.collect_agent_id = collect_agent_id
            self.channel = None
            self.stub = None
            self._connected = False
            self._initialized = True

    async def connect(self):
        try:
            logger.info(f"Connecting to alert server at {self.server_address}")
            self.channel = grpc.aio.insecure_channel(self.server_address)
            self.stub = alerts_pb2_grpc.AlertServiceStub(self.channel)
            self._connected = True
            logger.info("Connected to alert server successfully")
        except Exception as e:
            logger.error(f"Failed to connect to alert server: {e}")
            self._connected = False

    async def send_alert(self, violation: Dict):
        if not self._connected:
            await self.connect()

        if not self._connected:
            logger.error("Cannot send alert: not connected to server")
            return

        try:
            alert = alerts_pb2.Alert(
                node_id=violation.get('node_id'),
                collect_agent_id=self.collect_agent_id,
                alert_type=violation.get('metric_name'),
                severity='critical' if violation.get('violation_type') == 'exceeded_max' else 'warning',
                message=self._format_alert_message(violation),
                timestamp=violation.get('timestamp', int(time.time())),
                metadata={
                    'metric_value': str(violation.get('metric_value')),
                    'threshold_max': str(violation.get('threshold_max', '')),
                    'threshold_min': str(violation.get('threshold_min', '')),
                    'violation_type': violation.get('violation_type', '')
                }
            )

            response = await self.stub.SendAlert(alert)

            if response.success:
                logger.info(f"Alert sent successfully for {violation.get('metric_name')}")
            else:
                logger.warning(f"Alert send failed: {response.message}")

        except Exception as e:
            logger.error(f"Error sending alert: {e}")
            self._connected = False

    def _format_alert_message(self, violation: Dict) -> str:
        return (
            f"Threshold violation: {violation.get('metric_name')} "
            f"value {violation.get('metric_value')} "
            f"{violation.get('violation_type')} "
            f"(max: {violation.get('threshold_max')}, min: {violation.get('threshold_min')})"
        )

    async def close(self):
        if self.channel:
            await self.channel.close()
            self._connected = False
            logger.info("Alert client closed")
