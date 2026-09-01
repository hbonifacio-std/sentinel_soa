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
            "List of key atomic forensic indicators, entities, or artifacts extracted from the analysis. "
            "Each element MUST be a single technical value, term, or entity (e.g., IP address, hash, "
            "CVE ID, domain, payload, technique, or status word). "
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

