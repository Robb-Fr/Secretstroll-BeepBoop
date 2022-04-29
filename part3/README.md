# Part 3

The running environment for this part is the docker client, deployed as described in the handout README. We mainly developped in this one (as one of us is using a M1 chip computer). We assume the subscriptions, keys and credentials have been generated as explained in the sample run of the handout's README.

We recommand having a terminal for the the server and one for the client.

## Trace collection
We assume running in the server container
```Bash
cd server; python3 server.py run
```
While in the client container, we run:
```Bash
cd trace_data_extraction; chmod +x capture.sh; ./capture.sh
```
This launches the collection of trace data with the client code for grid cell ids from 1 to 100.

The collected trace for each query is indexed by the month, day and hour of collection and stored in the folder `trace_data_extraction/traces`.

_Bonus_: the `trace_data_extraction/tor_time.sh` script is run in the same conditions and produces text files storing the time took for each request to be performed with and without `-t` option on the client to activate or not tor. This has been used to test the correlation of execution time betweeen identical queries. Note that this requires the `bc` package installed with `apt-get install bc`.

## Data Cleaning and Feature Extraction
Those parts are performed by the `trace_data_extraction/trace_data_extraction.ipynb` file with jupyter notebook.

Note that the user will need to install the required python modules with `pip install -r requirements.txt`

Running all cells of this Notebook produces the `features.csv` file containing the feature the classifier can use.

## Training and classification
```Bash
python3 fingerprinting.py
```
Prints in the console the results of classification after 10-folds cross-validation using the features in `features.csv` file.