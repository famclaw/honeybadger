# SARIF Output Format

HoneyBadger now supports generating SARIF (Static Analysis Results Interchange Format) 2.1.0 output for integration with security tools and CI/CD pipelines.

## Usage

```bash
honeybadger scan <repo-url> --format sarif
```

## Output Structure

The SARIF output includes:

- **Version**: "2.1.0"
- **Schema**: "https://json.schemastore.org/sarif-2.1.0-rtm.5.json"
- **Tool**: honeybadger driver with name and version
- **Results**: Each finding becomes a SARIF result with:
  - `ruleId`: The rule identifier
  - `level`: Severity mapping (error, warning, note)
  - `message.text`: Finding message
  - `locations.physicalLocation.artifactLocation.uri`: File path
  - `locations.physicalLocation.region.startLine`: Line number
  - `properties`: Additional metadata including:
    - `rule_id`: The rule identifier
    - `more_info_url`: Link to more information about the rule
    - `references`: List of reference URLs
    - `package`: Package name (for CVE findings)
    - `version`: Package version (for CVE findings)
    - `ecosystem`: Package ecosystem (for CVE findings)
    - `cve_id`: CVE identifier (for CVE findings)
    - `fixed_in`: Fixed version (for CVE findings)

## Severity Mapping

| HoneyBadger Severity | SARIF Level |
|---------------------|-------------|
| CRITICAL            | error       |
| HIGH                | error       |
| MEDIUM              | warning     |
| LOW                 | note        |
| INFO                | note        |

## Example Output

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "honeybadger",
          "version": "0.0.0"
        }
      },
      "results": [
        {
          "ruleId": "rule-123",
          "level": "error",
          "message": {
            "text": "Potential secret found"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "test.go"
                },
                "region": {
                  "startLine": 10
                }
              }
            }
          ],
          "properties": {
            "rule_id": "rule-123",
            "more_info_url": "https://example.com/rule123",
            "references": ["ref1", "ref2"],
            "package": "my-package",
            "version": "1.0.0",
            "ecosystem": "npm",
            "cve_id": "CVE-2023-12345",
            "fixed_in": "1.1.0"
          }
        }
      ]
    }
  ]
}
```