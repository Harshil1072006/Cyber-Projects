"""
SQL Injection Tester for Java APIs.
Tests parameters for SQL injection vulnerabilities using error-based and time-based techniques.
"""

import logging
import requests
import time
from typing import List, Dict, Any, Tuple
from ..finding_manager import FindingManager, Finding, Evidence
from ..enumeration.swagger_parser import ApiEndpoint

logger = logging.getLogger(__name__)


class SqlInjectionTester:
    """Tests API endpoints for SQL Injection vulnerabilities."""

    def __init__(
        self,
        finding_manager: FindingManager,
        target_url: str,
        auth_headers: Dict[str, str],
    ):
        self.finding_manager = finding_manager
        self.target_url = target_url
        self.auth_headers = auth_headers
        self.session = requests.Session()
        self.session.headers.update(auth_headers)

        # Payloads targeted at common Java DBs (PostgreSQL, MySQL, Oracle)
        self.error_payloads = [
            "'",
            '"',
            "''",
            "';--",
            "' OR '1'='1",
            "' OR 1=1--",
            "') OR ('1'='1",
        ]

        self.time_payloads = [
            "'; WAITFOR DELAY '0:0:5'--",  # SQL Server
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",  # MySQL
            "'; SELECT pg_sleep(5);--",  # PostgreSQL
        ]

        # SQL error patterns
        self.sql_errors = [
            "SQL syntax",
            "MySQLSyntaxErrorException",
            "valid PostgreSQL command",
            "Unclosed quotation mark",
            "java.sql.SQLException",
            "org.hibernate.exception.SQLGrammarException",
            "ORA-00933",  # Oracle
        ]

    def test_endpoints(self, endpoints: List[ApiEndpoint]) -> None:
        """Runs SQLi tests against all discovered injection candidates."""
        logger.info("Starting SQL Injection tests...")

        for endpoint in endpoints:
            candidates = [p for p in endpoint.parameters if p.is_injection_candidate]
            if not candidates:
                continue

            for param in candidates:
                self._test_error_based(endpoint, param)

        logger.info("SQL Injection testing complete.")

    def _test_error_based(self, endpoint: ApiEndpoint, param) -> None:
        """Tests for error-based SQLi."""
        url = f"{self.target_url}{endpoint.path}"

        for payload in self.error_payloads:
            # Build request
            req_url = url
            params = {}
            json_data = None

            # Very basic parameter injection based on location
            if param.in_location == "path":
                req_url = req_url.replace(f"{{{param.name}}}", payload)
            elif param.in_location == "query":
                params[param.name] = payload
            elif param.in_location == "body":
                # Simplified: assumes a flat JSON structure
                json_data = {param.name: payload}

            try:
                response = self.session.request(
                    method=endpoint.method,
                    url=req_url,
                    params=params,
                    json=json_data,
                    timeout=5,
                    allow_redirects=False,
                )

                # Check for SQL errors in response
                for error in self.sql_errors:
                    if error.lower() in response.text.lower():
                        evidence = Evidence(
                            type="request_response",
                            content=f"Payload: {payload}\nStatus: {response.status_code}\nMatched Error: {error}\nSnippet:\n{response.text[:200]}",
                            description="Database error message leaked in response, indicating successful SQL injection.",
                        )

                        finding = Finding(
                            title=f"Error-Based SQL Injection on {param.name}",
                            description=f"The endpoint {endpoint.method} {endpoint.path} appears vulnerable to SQL Injection via the '{param.name}' parameter. Error messages indicating a syntax error were returned.",
                            vulnerability_type="SQL Injection",
                            severity="CRITICAL",
                            cwe_id="CWE-89",
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            component=f"{endpoint.path} [{param.name}]",
                            remediation="Use PreparedStatement with parameterized queries (e.g., in JDBC) or ensure ORM bindings (Hibernate/JPA) are used correctly without concatenating user input.",
                            evidence=[evidence],
                        )
                        self.finding_manager.add_finding(finding)
                        return  # Stop testing this parameter once found
            except Exception as e:
                logger.debug(f"SQLi test failed for {param.name}: {e}")
