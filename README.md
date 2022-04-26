# Secretstroll-BeepBoop
Secretstroll project of CS-523 Advanced Topics on Privacy Enhacing Technologies course at EPFL. Spring 2022.

See https://github.com/Robb-Fr/Secretstroll-BeepBoop-Report for the report repository.

Make sure all requirements are installed: `pip install -r requirements.txt`
Run tests:

```bash
# runs tests with 2 workers, 100 iterations per test
python3 -m pytest secretstroll --count=100 -n 2 --benchmark-disable
```

Run benchmark:
```bash
# runs benchmarks, skips tests and produces histogram
python3 -m pytest secretstroll --benchmark-enable --benchmark-only --benchmark-histogram --benchmark-autosave
```
