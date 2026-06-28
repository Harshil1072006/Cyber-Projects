"""
Mock responses for testing HTTP clients.
"""

MOCK_SWAGGER = {
    "swagger": "2.0",
    "paths": {
        "/api/users": {
            "get": {
                "summary": "Get users",
                "parameters": [{"name": "id", "in": "query", "type": "string"}],
            }
        }
    },
}
