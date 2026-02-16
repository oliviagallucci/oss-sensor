"""Binary diff stub: match functions by name/address; interface for future Diaphora integration."""

from oss_sensor.models import BinaryFeature, BinaryDiffStub


def compute_binary_diff_stub(
    features_from: list[BinaryFeature],
    features_to: list[BinaryFeature],
) -> list[BinaryDiffStub]:
    """
    Stub: match by symbol/function name (and address if present).
    Design allows plugging in Diaphora or other binary diff later.
    """
    syms_from = {f.value: f for f in features_from if f.feature_type == "symbols"}
    syms_to = {f.value: f for f in features_to if f.feature_type == "symbols"}
    stubs: list[BinaryDiffStub] = []
    for name, f_to in syms_to.items():
        f_from = syms_from.get(name)
        if f_from:
            stubs.append(
                BinaryDiffStub(
                    from_function=name,
                    to_function=name,
                    from_address=f_from.address,
                    to_address=f_to.address,
                    similarity_note="matched by name (stub)",
                )
            )
    # New symbols in "to" (added)
    for name in syms_to:
        if name not in syms_from:
            stubs.append(
                BinaryDiffStub(
                    from_function="",
                    to_function=name,
                    from_address=None,
                    to_address=syms_to[name].address,
                    similarity_note="added in to build",
                )
            )
    return stubs
