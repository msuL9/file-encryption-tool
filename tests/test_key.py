import pytest
from encryptor.key import derive_key

def test_derive_key():
    key1, salt1 = derive_key("testpass")
    assert len(key1) == 32
    assert len(salt1) == 16

    key2, _ = derive_key("testpass", salt1)
    assert key1 == key2

    key3, _ = derive_key("different", salt1)
    assert key1 != key3