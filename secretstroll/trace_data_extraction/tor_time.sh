#!/bin/bash
### ASSUMES A RUNNING SERVER

# we go back to the main folder to have the scripts and keys
cd ..
echo "================================================================================"
echo "Begining measure"
echo "================================================================================"
OUTPUT_MSG="Measure failed for trace:"
TIMES_TOR="Measured times with tor (in seconds):"
TIMES_NO_TOR="Measured times without tor (in seconds):"
# we go through 30 first grids, indexed by i (just enough to have a rough idea of the correlation)
for i in {1..30}
    do
        # !!! requires apt-get install bc (for sub second precision)
        start=$(date +%s.%N)
        # queries for cell i with tor
        python3 client.py grid $i -T restaurant -t
        query_status=$?
        if [ $query_status != 0 ]
        then
            echo "$OUTPUT_MSG (with tor):$i"
            # we don't want to continue a failed test
            cd trace_data_extraction
            exit 1
        else
            end=$(date +%s.%N)
            duration=$(echo "$(date +%s.%N) - $start" | bc)
            TIMES_TOR="$TIMES_TOR\n$i:$duration"
        fi
        # makes sure previous finished
        sleep 1
###############################################################################
        start=$(date +%s.%N)
        # queries for cell i without tor
        python3 client.py grid $i -T restaurant
        query_status=$?
        if [ $query_status != 0 ]
        then
            echo "$OUTPUT_MSG (without tor):$i"
            # we don't want to continue a failed test
            cd trace_data_extraction
            exit 1
        else
            end=$(date +%s.%N)
            duration=$(echo "$(date +%s.%N) - $start" | bc)
            TIMES_NO_TOR="$TIMES_NO_TOR\n$i:$duration"
        fi
        # makes sure previous finished
        sleep 1
    done
# we get back to the folder
cd trace_data_extraction
# -e makes sure the \n are line return
echo -e $TIMES_NO_TOR > times_no_tor.txt
echo -e $TIMES_TOR > times_tor.txt
exit 0