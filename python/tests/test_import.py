import pytest

def test_import():
    import dlisio

def test_printelfr():
    import dlisio
    dl = dlisio.load('206_05a-_3_DWL_DWL_WIRE_258276501.DLIS')

    for ex in dl.eflr:
        print(ex)

    assert False
