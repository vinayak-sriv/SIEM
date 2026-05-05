import pytest
from src.models import _severity_name

def test_severity_name_boundaries():
    # LOW boundaries
    assert _severity_name(0) == "LOW"
    assert _severity_name(9) == "LOW"
    
    # MEDIUM-HIGH boundaries
    assert _severity_name(10) == "MEDIUM-HIGH"
    assert _severity_name(11) == "MEDIUM-HIGH"
    
    # HIGH boundaries
    assert _severity_name(12) == "HIGH"
    assert _severity_name(14) == "HIGH"
    
    # CRITICAL boundaries
    assert _severity_name(15) == "CRITICAL"
    assert _severity_name(99) == "CRITICAL"
    
    # UNKNOWN boundaries (negative)
    assert _severity_name(-1) == "UNKNOWN"

def test_severity_name_type_errors():
    # _severity_name expects an int. Passing None or string should raise TypeError.
    with pytest.raises(TypeError):
        _severity_name(None)
    
    with pytest.raises(TypeError):
        _severity_name('bad')
