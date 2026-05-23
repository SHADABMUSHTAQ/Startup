import json
from datetime import datetime

class DatetimeEncoder(json.JSONEncoder):
    """Custom JSON Encoder that converts datetime objects to ISO strings."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def dumps(obj, **kwargs):
    kwargs.setdefault('cls', DatetimeEncoder)
    return json.dumps(obj, **kwargs)
