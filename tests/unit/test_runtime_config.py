from __future__ import annotations

import pytest

from kappa_box.runtime import RuntimeConfig

_REGISTERED_IMAGE = (
    "ghcr.io/nvidia/openshell-community/sandboxes/base@"
    "sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
)


def test_plaintext_gateway_requires_explicit_insecure_opt_in():
    with pytest.raises(
        ValueError, match="plaintext gateway requires explicit insecure opt-in"
    ):
        RuntimeConfig(
            profile_id="wsl2:l1@openshell-docker",
            distribution="kappa-box-ubuntu-24.04",
            gateway_endpoint="http://127.0.0.1:17670",
            openshell_binary="/usr/local/bin/openshell",
            approved_images=(_REGISTERED_IMAGE,),
        )
