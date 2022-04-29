# Part 1
The running environment we recommend is the client docker deployed exactly as explained in the handout README. We mainly developped in this one (as one of us is using a M1 chip computer). 

The user should open a terminal in this folder to run the commands.

## Running tests
### Running the tests for credential system
```Bash
pytest test_credential.py
```

### Running the tests for stroll system
```Bash
pytest test_stroll.py
```

## Communication cost evaluation
```Bash
pytest -s test_stroll.py
```
prints out to the console the number of bytes used by each credential artifact.

---

From this point, the user should make sure to have installed the requirements using `pip install -r requirements.txt`

---

## Benchmark
```Bash
pytest --benchmark-histogram --benchmark-autosave
```
Runs the benchmarks over every functions of `stroll` and `credential` modules, generates an histogram as a `.svg` file and stores the results in the folder `.benchmarks/Linux-CPython-3.9-64bit` as json file.

```Bash
pytest-benchmark compare 0 --histogram
```
Compares the results of the 1000 first benchmark saved results generated as above and produces an histogram.
## Coverage
```Bash
pytest --cov-report=html --cov=credential test_credential.py

pytest --cov-report=html --cov=stroll test_stroll.py
```
Respectively evaluates coverage of credential and stroll modules. The results are stored in a folder `htmlcov` where you can see those with the file `index.html`