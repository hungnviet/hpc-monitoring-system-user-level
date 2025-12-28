#!/usr/bin/env python3

import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

from config import ConfigurationManager
from server import CollectAgentServer
from utils import get_logger


logger = get_logger(__name__)


async def main():
    try:
        config_manager = ConfigurationManager()
        config = config_manager.load()

        server = CollectAgentServer(config)
        await server.start()

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
