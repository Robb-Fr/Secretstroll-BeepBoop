# Secretstroll-BeepBoop
Secretstroll project of CS-523 Advanced Topics on Privacy Enhacing Technologies course at EPFL. Spring 2022.

See https://github.com/Robb-Fr/Secretstroll-BeepBoop-Report for the report repository.

Make sure all requirements are installed: `pip install -r requirements.txt`
Run tests:

```bash
# runs with 2 workers, 100 iterations per test
python3 -m pytest secretstroll -n 2 --count=100
```

Run benchmark:
```bash
# runs with the credential.py benchmark, skips tests and produces histogram
python3 -m pytest secretstroll/benchmark_credential.py --benchmark-only  --benchmark-histogram
```