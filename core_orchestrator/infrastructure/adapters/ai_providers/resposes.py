from typing import List

from pydantic import BaseModel, Field


class ResponseForensic(BaseModel):
    response_markdown: str = Field(
        ...,
        description=(
            "Full forensic analysis report written in complete, professional Markdown format. "
            "Must include sections such as Summary, Methodology/Tools Queried, Detailed Findings "
            "(payloads, routes, attacker IPs, timestamps), and Recommendations or Next Steps. "
            "If no threats or evidence are found, explicitly detail the checks performed and state "
            "that no malicious activity was identified."
        )
    )
    highlighted: List[str] = Field(
        ...,
        description=(
            "List of key forensic indicators formatted strictly as 'CATEGORY: VALUE'. "
            "Allowed categories and rules:"
            "- 'SEVERITY': Overall risk level (e.g., 'SEVERITY: HIGH'). Include exactly ONE."
            "- 'SOURCE': Targeted application or service ID (e.g., 'SOURCE: api-core-005')."
            "- 'ATTACK': Identified threat or technique (e.g., 'ATTACK: SQL Injection Attempt', 'ATTACK: Credential Fuzzing')."
            "- 'TOOL': Specific user-agent or tool detected (e.g., 'TOOL: sqlmap/1.6#stable')."
            "- 'IP': Attacker origin IP address (e.g., 'IP: 198.51.100.42')."
            "- 'ROUTE': Affected route with HTTP status in parentheses (e.g., 'ROUTE: /api/v1/products (HTTP 500)')."
            "DO NOT output raw strings without a category prefix. DO NOT output plain timestamps or isolated HTTP codes."
        )
    )

    def add_highlight(self, item: str) -> None:
        """
        Adds a new highlighted item to the list of highlighted items.

        Parameters:
        item: str
            The string item to be added to the highlighted list. Leading and trailing
            whitespace will be removed before adding.

        """
        if item and item.strip():
            self.highlighted.append(item.strip())

    def add_highlights(self, items: List[str]) -> None:
        """
        Adds highlights to the current object based on the provided list of items.

        This method iterates through a list of items, calling the add_highlight method
        for each item in the list.

        Args:
            items (List[str]): A list of strings representing the items to be highlighted.
        """
        for item in items:
            self.add_highlight(item)

