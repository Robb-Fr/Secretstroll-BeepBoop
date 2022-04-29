# Part 2 
This part has been test run in the client container deployed as described by the handout's README. You may need to install the required package with `pip install -r requirements.txt`

The privacy evaluation was fully conducted in the `privacy_evaluation/PrivacyEval.ipynb` notebook. It uses the provided `privacy_evaluation/grid.py` and `privacy_evaluation/queries.csv`, `privacy_evaluation/pois.csv` files. 

It is divided in the following parts:
* Package Imports: the necessary package imports for the privacy evaluation.
* Data Imports & Examination: Importing the csv files and examining the contents as well as extracting general statistics. 
* Data Analysis: Creating visualisation for the data. 
* Data Improvements: enhancing the data (e.g. timestamps and coordinates)
* Data Analysis (Attack): extracting insight from the data to perform attacks and comparing results given certain mitigations. 
* Defence: explanation of the mitigations.