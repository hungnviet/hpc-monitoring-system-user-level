import signal
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent / "collector"))
from main import VirtualSensor

sys.path.insert(0, str(Path(__file__).parent / "client"))
from main import MetricsStreamClient

from config import ConfigurationManager
from utils import get_logger


logger = get_logger(__name__)


class ComputeNodeAgent:
    def __init__(self, config_path: str = "infra.json"):
        self.config_path = config_path
        self.config_manager = ConfigurationManager()

        self.grpc_client: Optional[MetricsStreamClient] = None
        self.sensor: Optional[VirtualSensor] = None

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, initiating shutdown")
        self.shutdown()

    def _collection_loop(self):
        logger.info("Starting collection loop")
        config = self.config_manager.config
        collection_enabled = self.config_manager.collection_enabled
        stop_event = self.config_manager.stop_event

        while not stop_event.is_set():
            if not collection_enabled.is_set():
                collection_enabled.wait(timeout=1)
                continue

            try:
                process_metrics, system_metrics = self.sensor.collect(config.collection_window)

                if self.grpc_client:
                    success = self.grpc_client.send_metrics(
                        process_data=process_metrics,
                        system_data=system_metrics,
                        node_id=config.node_id,
                        collection_window=config.collection_window
                    )

                    if success:
                        gpu_count = len(system_metrics.get("gpus", []))
                        logger.info(
                            f"Metrics sent: CPU={system_metrics.get('cpu_usage_percent', 0):.1f}%, "
                            f"MEM={system_metrics.get('memory_usage_percent', 0):.1f}%, "
                            f"GPUs={gpu_count}, Processes={len(process_metrics)}"
                        )
                    else:
                        logger.warning("Failed to send metrics")

            except Exception as e:
                logger.error(f"Error in collection loop: {e}", exc_info=True)
                time.sleep(1)

    def run(self):
        logger.info("=" * 60)
        logger.info("Starting Compute Node Agent")
        logger.info("=" * 60)

        try:
            config = self.config_manager.load(self.config_path)
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
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
            logger.info(f"Initializing gRPC client to {config.target_collect_agent}...")
            self.grpc_client = MetricsStreamClient(
                server_address=config.target_collect_agent,
                max_retries=3
            )
            logger.info("gRPC client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize gRPC client: {e}")
            return

        logger.info("Starting background tasks...")
        self.config_manager.start_background_tasks()

        try:
            self._collection_loop()
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        except Exception as e:
            logger.error(f"Fatal error in main loop: {e}", exc_info=True)
        finally:
            self.shutdown()

    def shutdown(self):
        if self.config_manager.stop_event.is_set():
            return

        logger.info("=" * 60)
        logger.info("Shutting down Compute Node Agent")
        logger.info("=" * 60)

        self.config_manager.shutdown()

        if self.grpc_client:
            logger.info("Closing gRPC client...")
            self.grpc_client.close()

        if self.sensor:
            logger.info("Closing VirtualSensor...")
            self.sensor.close()

        logger.info("Shutdown complete")


def main():
    agent = ComputeNodeAgent()
    agent.run()


if __name__ == "__main__":
    main()
