"""
Attack Simulator.
Loads and executes the appropriate Scapy-based attack logic.
"""

import logging
from typing import Dict, Any, Type

from .config_manager import FrameworkConfig
from .attacks.base_attack import BaseAttack
from .attacks.arp_spoofing import ArpSpoofing
from .attacks.port_scanning import PortScanning
from .attacks.dos_attack import DosAttack
from .attacks.protocol_anomaly import ProtocolAnomaly

class AttackSimulator:
    """Manages the creation and execution of network attacks."""

    def __init__(self, config: FrameworkConfig):
        """
        Initialize the AttackSimulator.
        
        Args:
            config: Framework configuration.
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Registry of supported attacks
        self.attacks: Dict[str, Type[BaseAttack]] = {
            "ARP_SPOOF": ArpSpoofing,
            "PORT_SCAN": PortScanning,
            "DOS": DosAttack,
            "PROTOCOL_ANOMALY": ProtocolAnomaly,
        }

    def simulate_attack(self, attack_type: str, parameters: Dict[str, Any]) -> None:
        """
        Simulates the requested attack type.
        
        Args:
            attack_type: The string identifier for the attack.
            parameters: Dictionary of attack-specific parameters.
        """
        self.logger.info(f"Simulating attack: {attack_type} with parameters {parameters}")
        
        attack_class = self.attacks.get(attack_type.upper())
        if not attack_class:
            self.logger.error(f"Unsupported attack type: {attack_type}")
            return
            
        try:
            attack_instance = attack_class(self.config)
            attack_instance.execute(parameters)
        except Exception as e:
            self.logger.error(f"Failed to simulate attack {attack_type}: {e}")
            raise
