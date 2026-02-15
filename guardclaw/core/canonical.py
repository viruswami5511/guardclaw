def canonicalize(obj: dict) -> str:
    """
    Convert object to canonical JSON string.
    
    Rules:
    1. Keys sorted alphabetically
    2. No whitespace
    3. Explicit field allow-list
    4. UTC timestamps as ISO8601
    5. Enums as string values
    """
