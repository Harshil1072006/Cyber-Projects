import os
import json
import logging
try:
    import hvac
except ImportError:
    hvac = None

# Configure minimal logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class VaultClient:
    """
    Enterprise Secrets Abstraction Layer.
    Resolves secrets from HashiCorp Vault, Jenkins Credentials, or local .env fallback.
    """
    
    def __init__(self, config_path="gate_config.json"):
        self.provider = "env"
        self.vault_config = {}
        self.client = None
        
        self._load_config(config_path)
        self._initialize_provider()

    def _load_config(self, config_path):
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    self.provider = config.get("secrets_provider", "env").lower()
                    self.vault_config = config.get("vault_config", {})
            except Exception as e:
                logger.warning(f"Failed to load config: {e}. Defaulting to 'env' provider.")
        else:
            logger.warning(f"{config_path} not found. Defaulting to 'env' provider.")

    def _initialize_provider(self):
        if self.provider == "vault":
            if not hvac:
                logger.error("hvac library not installed. pip install hvac")
                self.provider = "env"
                return
                
            addr = os.getenv("VAULT_ADDR", self.vault_config.get("address", ""))
            token_env = self.vault_config.get("token_env", "VAULT_TOKEN")
            token = os.getenv(token_env)
            
            if addr and token:
                try:
                    self.client = hvac.Client(url=addr, token=token)
                    if self.client.is_authenticated():
                        logger.info(f"Successfully authenticated to HashiCorp Vault at {addr}")
                    else:
                        logger.warning("Vault authentication failed. Falling back to env.")
                        self.provider = "env"
                except Exception as e:
                    logger.warning(f"Vault connection error: {e}. Falling back to env.")
                    self.provider = "env"
            else:
                logger.warning("Vault address or token missing. Falling back to env.")
                self.provider = "env"

    def get_secret(self, key, default=None):
        """
        Retrieve a secret based on the active provider.
        """
        if self.provider == "vault" and self.client:
            path = self.vault_config.get("secret_path", "secret/data/devsecops-pipeline")
            mount = self.vault_config.get("mount_point", "secret")
            try:
                # Vault KV v2 format
                response = self.client.secrets.kv.v2.read_secret_version(
                    mount_point=mount,
                    path=path.replace(f"{mount}/data/", "")
                )
                secret_value = response['data']['data'].get(key)
                if secret_value:
                    return secret_value
            except Exception as e:
                logger.debug(f"Failed to read {key} from Vault: {e}")
                
        # Fallback to env / Jenkins injected credentials
        return os.getenv(key, default)

# Singleton instance for easy import
secrets = VaultClient()

if __name__ == "__main__":
    # Test execution
    print(f"Active Provider: {secrets.provider}")
    print(f"SLACK_WEBHOOK_URL: {secrets.get_secret('SLACK_WEBHOOK_URL', 'Not found')}")
