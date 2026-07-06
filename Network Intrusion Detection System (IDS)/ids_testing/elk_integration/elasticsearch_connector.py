"""
Elasticsearch Connector.
Handles querying and pushing alerts to Elasticsearch.
"""

import logging
from typing import Dict, Any, List, Optional
try:
    from elasticsearch import Elasticsearch # type: ignore
    HAS_ES = True
except ImportError:
    HAS_ES = False

from ..config_manager import ELKConfig

class ElasticsearchConnector:
    """Manages connections to Elasticsearch."""

    def __init__(self, config: ELKConfig):
        """
        Initialize the connector.
        
        Args:
            config: ELK configuration.
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.client = None
        
        if HAS_ES:
            self._connect()
        else:
            self.logger.warning("Elasticsearch module not installed. ELK integration disabled.")

    def _connect(self) -> None:
        """Establishes connection to Elasticsearch."""
        try:
            auth = None
            if self.config.username and self.config.password:
                auth = (self.config.username, self.config.password)
                
            self.client = Elasticsearch(
                self.config.elasticsearch_url,
                basic_auth=auth,
                verify_certs=False
            )
            
            if self.client.ping():
                self.logger.info("Successfully connected to Elasticsearch.")
            else:
                self.logger.warning("Could not ping Elasticsearch.")
        except Exception as e:
            self.logger.error(f"Failed to connect to Elasticsearch: {e}")
            self.client = None

    def push_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Pushes a single alert to Elasticsearch.
        """
        if not self.client:
            return False
            
        try:
            # Simple indexing for test purposes
            self.client.index(
                index=f"{self.config.index_prefix}alerts",
                document=alert
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to index alert: {e}")
            return False
