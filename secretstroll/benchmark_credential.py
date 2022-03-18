from test_credential import (
    test_sign_success,
    test_obtaining_credentials_succes,
    test_disclosure_proof_verification,
)


def test_sign(benchmark):
    benchmark(test_sign_success)


def test_obtaining_credentials(benchmark):
    benchmark(test_obtaining_credentials_succes)


def test_showing_protocol(benchmark):
    benchmark(test_disclosure_proof_verification)
