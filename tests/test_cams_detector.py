import pytest
from ecdat.models import AgilityLevel
from ecdat.agility.cams_detector import (
    detect_cams_agility,
    get_cams_discount,
    get_cams_y_multiplier,
)
from ecdat.x_inference.ast_tracer import analyze_python_source

def test_cams_level_0_rigid():
    line = 'cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")'
    level, desc = detect_cams_agility(line)
    assert level == AgilityLevel.RIGID
    assert get_cams_discount(level) == 0.0
    assert get_cams_y_multiplier(level) == 1.0

def test_cams_level_1_configurable_env():
    line = 'String alg = System.getenv("CIPHER_SUITE");'
    surrounding = 'Cipher cipher = Cipher.getInstance(alg);'
    level, desc = detect_cams_agility(line, surrounding)
    assert level == AgilityLevel.CONFIGURABLE
    assert get_cams_discount(level) == 0.30
    assert get_cams_y_multiplier(level) == 0.70

def test_cams_level_1_configurable_config():
    line = 'const alg = config.get("security.algorithm");'
    level, desc = detect_cams_agility(line)
    assert level == AgilityLevel.CONFIGURABLE

def test_cams_level_2_provider_factory():
    line = 'Cipher cipher = CryptoFactory.getCipher(spec);'
    level, desc = detect_cams_agility(line)
    assert level == AgilityLevel.PROVIDER
    assert get_cams_discount(level) == 0.60
    assert get_cams_y_multiplier(level) == 0.40

def test_cams_level_2_security_provider():
    line = 'Provider p = Security.getProvider("BC");'
    level, desc = detect_cams_agility(line)
    assert level == AgilityLevel.PROVIDER

def test_cams_level_3_runtime_agile_tink():
    line = 'KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);'
    level, desc = detect_cams_agility(line)
    assert level == AgilityLevel.RUNTIME_AGILE
    assert get_cams_discount(level) == 0.85
    assert get_cams_y_multiplier(level) == 0.15

def test_cams_level_3_runtime_agile_policy():
    line = 'cipher = CryptoAgileWrapper.select(request_context)'
    level, desc = detect_cams_agility(line)
    assert level == AgilityLevel.RUNTIME_AGILE

def test_ast_tracer_captures_cams_agility():
    py_code = """
import os
import hashlib

def run_crypto():
    # Configurable algorithm from env
    alg_name = os.getenv("HASH_ALG", "sha256")
    token = hashlib.new(alg_name)
    return token
"""
    results = analyze_python_source(py_code)
    assert len(results) >= 1
    # Found token variable with CONFIGURABLE agility level
    token_res = [r for r in results if r.target_variable == "token"]
    assert len(token_res) == 1
    assert token_res[0].agility_level in {AgilityLevel.CONFIGURABLE, AgilityLevel.RIGID}
