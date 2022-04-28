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
# runs benchmarks, skips tests, produces histogram and saves the benchmarked data
python3 -m pytest secretstroll --benchmark-enable --benchmark-only --benchmark-histogram --benchmark-autosave
```

Commands used to produces the benchmarks in `.benchmarks` folder (assumes a working `pytest` command):
```bash
# runs benchmarks for credential.py, skips tests, produces histogram and saves the benchmarked data with correct names (for arm64 4 cores and 4 subscriptions and warms up the evaluation)
pytest secretstroll/test_credential.py --benchmark-enable --benchmark-only --benchmark-histogram='credential_8_subscriptions_arm64_4cores' --benchmark-save='credential_8_subscriptions_arm64_4cores' --benchmark-warmup='on'
# merges benchmarks of previous evaluations
pytest-benchmark compare 0001 0002 0003 --histogram='credential_compare_arm64_4cores'
# runs benchmarks for stroll.py, skips tests, produces histogram and saves the benchmarked data with correct names (for arm64 4 cores and warms up the evaluation)
pytest secretstroll/test_stroll.py --benchmark-enable --benchmark-only --benchmark-histogram='stroll_arm64_4cores' --benchmark-save='stroll_arm64_4cores' --benchmark-warmup='on'
```

## Part 2 

The privacy evaluation was fully conducted in the `PrivacyEval.ipynb` notebook. It uses the provided `grid.py` and `queries.csv`, `pois.csv` files. 

It is divided in the following parts:
* Package Imports: the necessary package imports for the privacy evaluation.
* Data Imports & Examination: Importing the csv files and examining the contents as well as extracting general statistics. 
* Data Analysis: Creating visualisation for the data. 
* Data Improvements: enhancing the data (e.g. timestamps and coordinates)
* Data Analysis (Attack): extracting insight from the data to perform attacks and comparing results given certain mitigations. 
* Defence: explanation of the mitigations. 



