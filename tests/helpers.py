import dns


class MockWhois:
    pass

    # TODO


class MockResolver:
    class MockRRSet:
        def __init__(self, answer):
            self.answer = answer

        def to_text(self):
            return self.answer

    def __init__(self, mock_responses):
        self.mock_responses = mock_responses

    async def resolve(self, query_name, rdtype="A"):
        print(f"MockResolver is being called with: {query_name} and {rdtype}")  # Debug line

        # Check if NXDOMAIN should be raised for the given domain.
        if query_name in self.mock_responses.get("_NXDOMAIN", []):
            raise dns.resolver.NXDOMAIN

        answers = self.mock_responses.get(query_name, {}).get(rdtype, [])
        print(f"MockResolver is returning: {answers}")  # Debug line

        return [self.MockRRSet(answer) for answer in answers]
