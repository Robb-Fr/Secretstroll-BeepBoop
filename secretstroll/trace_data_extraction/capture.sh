#!/bin/bash
### ASSUMES A RUNNING SERVER

# we go back to the main folder to have the scripts and keys
cd ..
echo "================================================================================"
echo "Begining capture"
echo "================================================================================"
OUTPUT_MSG="Capture failed for traces (none if empty): "
# we go through every cell, indexed by i
for i in {1..100}
    do
        # we format the trace filename with the day-month-hour format and cell index
        # the day-month-hour will help differentiate between different traces for same cell (but different captures)
        # (I assume I will take 1 hour to capture for all cells)
        trace_name=$(date +"trace_data_extraction/traces/trace_%d_%m_%Hh_grid_$i.pcap")
        echo "Capturing $trace_name ..."
        # we capture to the file `trace_name`
        # -s 64 saves only the first 64 bytes (contains all headers and 3 bytes of the envrypted data)
        # greater 55 isolates packets only of length > 54 (basically removes packets having no tcp payload)
        # tcp keeps only tcp packets to make sure we only keep traffic relevant for the application
        tcpdump -w $trace_name -s 64 greater 55 and tcp &
        # records the process id of the previously launched process
        PID=$!
        # makes sure capture is setup
        sleep 1
        # queries for cell i
        python3 client.py grid $i -T restaurant -t
        # we test if the query failed (returned not 0), we'll inform the user at the end
        query_status=$?
        if [ $query_status != 0 ]
        then
            OUTPUT_MSG="$OUTPUT_MSG$i "
        fi
        # makes sure the capture captured all
        sleep 3.5
        # sends SIGINT to the application
        kill -2 $PID
        sleep 0.3
    done
echo "================================================================================"
echo $OUTPUT_MSG
echo "================================================================================"
# we get back to the folder
cd trace_data_extraction