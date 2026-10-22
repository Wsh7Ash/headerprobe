from headerprobe.probe import RELEVANT
def test_relevant_headers():
    assert 'set-cookie' in RELEVANT
    assert 'www-authenticate' in RELEVANT
