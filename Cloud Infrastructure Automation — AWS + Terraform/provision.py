import os
import subprocess
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("provisioner")

class Provisioner:
    def __init__(self, env: str, working_dir: str):
        self.env = env
        self.working_dir = Path(working_dir)
        
    def validate(self):
        if not self.working_dir.exists():
            logger.error(f"Directory {self.working_dir} does not exist.")
            return False
        return True

    def run_terraform(self, action: str):
        cmd = ["terraform", action, "-var", f"environment={self.env}"]
        if action == "apply":
            cmd.append("-auto-approve")
            
        logger.info(f"Running: {' '.join(cmd)}")
        try:
            # We mock subprocess for tests
            result = subprocess.run(cmd, cwd=self.working_dir, check=True, capture_output=True, text=True)
            logger.info(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Terraform failed: {e.stderr}")
            return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", required=True, choices=["dev", "staging", "prod"])
    parser.add_argument("--action", required=True, choices=["plan", "apply", "destroy"])
    parser.add_argument("--dir", default="./terraform")
    args = parser.parse_args()

    prov = Provisioner(args.env, args.dir)
    if prov.validate():
        prov.run_terraform(args.action)

if __name__ == "__main__":
    main()
