"""
Base Attack Template.
Provides the abstract class for all attack simulations.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any

from scapy.all import send, sendp, conf # type: ignore

class BaseAttack(ABC):
    """Abstract base class for network attacks."""

    def __init__(self, config: Any):
        """
        Initialize the base attack.
        
        Args:
            config: Framework configuration object.
        """
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Disable Scapy verbosity
        conf.verb = 0

    @abstractmethod
    def build_packets(self, parameters: Dict[str, Any]) -> Any:
        """
        Constructs the packets needed for the attack.
        
        Args:
            parameters: Attack-specific parameters.
            
        Returns:
            Scapy packet or list of packets.
        """
        pass

    def execute(self, parameters: Dict[str, Any]) -> None:
        """
        Executes the attack by sending built packets.
        
        Args:
            parameters: Attack parameters.
        """
        try:
            self.logger.info(f"Executing {self.__class__.__name__}...")
            packets = self.build_packets(parameters)
            self.send_packets(packets, parameters)
            self.logger.info(f"Execution of {self.__class__.__name__} complete.")
        except Exception as e:
            self.logger.error(f"Error during {self.__class__.__name__}: {e}")
            raise

    def send_packets(self, packets: Any, parameters: Dict[str, Any]) -> None:
        """
        Sends the packets via Scapy. Can be overridden for custom logic.
        
        Args:
            packets: Scapy packets to send.
            parameters: Additional sending parameters (e.g., inter-packet delay).
        """
        interface = self.config.network.interface
        # Using send() for layer 3, sendp() for layer 2
        # A robust implementation would determine this dynamically.
        # For our simulation framework, we will default to Layer 3 send()
        # unless overridden by specific layer 2 attacks (like ARP).
        send(packets, iface=interface, verbose=False)
