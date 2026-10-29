"""Local validation for CPE selections against declared software inventory."""


def split_cpe_fields(cpe_name: str) -> list[str] | None:
    if not cpe_name.startswith("cpe:2.3:"):
        return None
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in cpe_name[len("cpe:2.3:"):]:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        return None
    fields.append("".join(current))
    return fields if len(fields) == 11 else None


def _identity(value: str) -> str:
    return "".join(char for char in value.casefold() if char.isalnum())


def cpe_inventory_mismatch(cpe_name: str, vendor: str, product: str, version: str) -> str | None:
    """Return a reason when a CPE is malformed or contradicts the inventory."""
    fields = split_cpe_fields(cpe_name)
    if fields is None:
        return "CPE must be a well-formed CPE 2.3 formatted string."
    part, cpe_vendor, cpe_product, cpe_version = fields[:4]
    if part not in {"a", "o"}:
        return "CPE must describe an application or operating system in the software inventory."
    if cpe_vendor in {"", "*", "-"} or cpe_product in {"", "*", "-"}:
        return "CPE vendor and product must identify a specific inventory item."
    if _identity(cpe_vendor) != _identity(vendor):
        return "CPE vendor does not match the selected software inventory."
    if _identity(cpe_product) != _identity(product):
        return "CPE product does not match the selected software inventory."
    if cpe_version in {"", "*", "-"} or cpe_version.casefold() != version.strip().casefold():
        return "CPE version must exactly match the selected software inventory version."
    return None


def demo_cpe_name(vendor: str, product: str, version: str) -> str | None:
    """Build an offline synthetic CPE candidate that matches one inventory row."""
    def escape(value: str) -> str:
        return "".join("\\" + char if char in r'\\?*!"#$%&\'()+,/:;<=>@[]^`{|}~ ' else char
                       for char in value.strip())

    if not vendor.strip() or not product.strip() or not version.strip():
        return None
    cpe = f"cpe:2.3:a:{escape(vendor.casefold())}:{escape(product.casefold())}:{escape(version)}:*:*:*:*:*:*:*"
    return cpe if cpe_inventory_mismatch(cpe, vendor, product, version) is None else None
