def load_item(item_id: int) -> dict:
    return {"id": item_id}


def export_item(data: dict) -> str:
    return str(data)


class Exporter:
    def run(self, data: dict) -> str:
        return export_item(data)
