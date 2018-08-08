import pytest

import dlisio

def test_load():
    with dlisio.load('206_05a-_3_DWL_DWL_WIRE_258276498.DLIS') as f:
        print(f.label)
        assert False
