def process_data(data):
    try:
        return data["value"]
    except Exception:
        return None