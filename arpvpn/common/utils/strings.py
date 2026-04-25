from typing import List


def list_to_str(_list: list, separator=", ") -> str:
    length = len(_list)
    text = ""
    count = 0
    for item in _list:
        if count < length - 1:
            text += item + separator
        else:
            text += item
        count += 1
    return text


def str_to_list(string: str, separator: str = "\n") -> List[str]:
    candidate = str(string or "")
    chunks = candidate.split(separator)
    items = []
    for cmd in chunks:
        normalized = str(cmd or "").strip()
        if normalized:
            items.append(normalized)
    return items
