import argparse
import sys
import logging
from java_security_assessment.config_manager import ConfigManager
from java_security_assessment.assessment_orchestrator import AssessmentOrchestrator
from java_security_assessment.utils.logger import setup_logger


def main():
    parser = argparse.ArgumentParser(
        description="Java Enterprise App Security Assessment"
    )
    parser.add_证券 = argparse.ArgumentParser(
        description="Java Enterprise App Security Assessment"
    )
    parser.add_argument(
        "-c", "--config", required=True, help="Path to configuration file"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    log_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_logger(log_level)

    try:
        config_manager = ConfigManager(args.config)
        config = config_manager.get_config()

        orchestrator = AssessmentOrchestrator(config)
        orchestrator.run_assessment()

    except Exception as e:
        logger.critical(f"Fatal error during assessment: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
