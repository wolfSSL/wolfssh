#!/bin/bash

KEY="$PWD/keys/hansel-key-ecc.pem"
TEST_FILE="$PWD/test"
FILE_SIZES=("5000" "10000" "50000" "100000" "150000" "200000" "250000" "300000" "350000" "400000" "500000" "1000000" "2000000")
TRANSFER_MBS=""
NUMBER_RUNS=10
LOG_FILE="$PWD/log.csv"
COMPARE_TO=""
AVERAGE_FILE=""

if [ -z $1 ]; then
    echo "Assuming default server port of 22 (pass port number as first"
    echo "argument if wanting to connect to a different port)"
    PORT=22
else
    PORT="$1"
fi

# Print the last transfer rate in the sftp progress output as MB/s
parse_openssh_rate() {
    TRANSFER_MBS="$(tr '\r' '\n' < "$1" | awk '
        {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[0-9.]+[KMG]?B\/s$/) {
                    v = $i; u = $i
                    sub(/[KMG]?B\/s$/, "", v)
                    sub(/^[0-9.]+/, "", u)
                    if (u == "B/s") v /= 1024 * 1024
                    else if (u == "KB/s") v /= 1024
                    else if (u == "GB/s") v *= 1024
                    rate = v
                }
            }
        }
        END { if (rate != "") printf "%.3f", rate }')"
    if [ -n "$TRANSFER_MBS" ]; then
        printf " $TRANSFER_MBS" >> $LOG_FILE
    else
        echo "Failed to parse sftp rate from $1" >&2
        cat "$1" >&2
        exit 1
    fi
}

do_openssh_put_test() {
    cp $TEST_FILE $TEST_FILE-out
    sftp_command="timeout 30 sftp -P $PORT -o BatchMode=yes -o StrictHostKeyChecking=no -i $KEY $USER@127.0.0.1"
    output_file="sftp_log.txt"

    # Start the script command to capture the sftp session
script -qec "$sftp_command << EOF
    put $TEST_FILE $TEST_FILE-out
    bye
EOF" /dev/null > $output_file 2>&1
    if [ $? -ne 0 ]; then
        echo "OpenSSH SFTP transfer failed" >&2
        cat $output_file >&2
        exit 1
    fi
    parse_openssh_rate $output_file
}

do_openssh_get_test() {
    cp $TEST_FILE $TEST_FILE-out
    sftp_command="timeout 30 sftp -P $PORT -o BatchMode=yes -o StrictHostKeyChecking=no -i $KEY $USER@127.0.0.1"
    output_file="sftp_log.txt"

    # Start the script command to capture the sftp session
script -qec "$sftp_command << EOF
    get $TEST_FILE $TEST_FILE-out
    bye
EOF" /dev/null > $output_file 2>&1
    if [ $? -ne 0 ]; then
        echo "OpenSSH SFTP transfer failed" >&2
        cat $output_file >&2
        exit 1
    fi
    parse_openssh_rate $output_file
}

do_wolfssh_put_test() {
    cp $TEST_FILE $TEST_FILE-out
    if ! RESULT=$(timeout 30 ./examples/sftpclient/wolfsftp -g -l $TEST_FILE -r $TEST_FILE-out -i $PWD/keys/hansel-key-ecc.der -j $PWD/keys/hansel-key-ecc.pub -u $USER -p $PORT); then
        echo "wolfSSH SFTP transfer failed: $RESULT" >&2
        exit 1
    fi
    TRANSFER_MBS="$(echo "$RESULT" | awk '/^Transferred .*MB\/s$/ {sub(/MB\/s$/, "", $NF); print $NF}')"
    if [ -z "$TRANSFER_MBS" ]; then
        echo "Failed to parse wolfSSH rate: $RESULT" >&2
        exit 1
    fi
    printf " $TRANSFER_MBS" >> $LOG_FILE
}

do_wolfssh_get_test() {
    cp $TEST_FILE $TEST_FILE-out
    if ! RESULT=$(timeout 30 ./examples/sftpclient/wolfsftp -G -l $TEST_FILE-out -r $TEST_FILE -i $PWD/keys/hansel-key-ecc.der -j $PWD/keys/hansel-key-ecc.pub -u $USER -p $PORT); then
        echo "wolfSSH SFTP transfer failed: $RESULT" >&2
        exit 1
    fi
    TRANSFER_MBS="$(echo "$RESULT" | awk '/^Transferred .*MB\/s$/ {sub(/MB\/s$/, "", $NF); print $NF}')"
    if [ -z "$TRANSFER_MBS" ]; then
        echo "Failed to parse wolfSSH rate: $RESULT" >&2
        exit 1
    fi
    printf " $TRANSFER_MBS" >> $LOG_FILE
}

# Create a log with averages
do_create_average() {
    awk -F', ' '$2 + 0 > 0 {sum[$1]+=$2; count[$1]++} END {for (i in sum) print i, sum[i]/count[i]}' "$LOG_FILE" | sort -n > "$AVERAGE_FILE"
    sed -i 's/ /, /' $AVERAGE_FILE
}


do_create_plot() {
    gnuplot -e "set title '$TITLE';set ylabel 'MB/s' rotate by 90;set xlabel 'File Size in Bytes';set grid; set format x \"%2.1t×10^{%L}\"; set term pngcairo enhanced;set output '$OUTPUT_FILE';plot '$LOG_FILE' using 1:2, '$AVERAGE_FILE' with lines lc rgb 'red' lw 2, '$COMPARE_TO' with lines lc rgb 'gold' lw 2"
}

echo "Starting tests"
echo "Getting the average over $NUMBER_RUNS runs"

# create openssh average if not found
AVERAGE_FILE="$PWD/openssh-average-upload.csv"
if [ ! -f "$AVERAGE_FILE" ]; then
    echo "Collecting openssh average upload"
    rm -f $LOG_FILE && touch $LOG_FILE
    for run in $(seq 1 $NUMBER_RUNS); do
        printf "Run $run: "
        for i in "${FILE_SIZES[@]}"; do
            tail -c "$i" /dev/urandom > "$TEST_FILE"
            printf "$i," >> $LOG_FILE
            do_openssh_put_test
            printf "\n" >> $LOG_FILE
        done
        printf "done\n"
    done

    do_create_average
    echo ""
fi

# create wolfssh average upload
echo "Collecting wolfssh average upload"
rm -f $LOG_FILE && touch $LOG_FILE
for run in $(seq 1 $NUMBER_RUNS); do
    printf "Run $run: "
    for i in "${FILE_SIZES[@]}"; do
        tail -c "$i" /dev/urandom > "$TEST_FILE"
        printf "$i," >> $LOG_FILE
        do_wolfssh_put_test
        printf "\n" >> $LOG_FILE
    done
    printf "done\n"
done

# compile and plot the results of average upload
AVERAGE_FILE="$PWD/wolfssh-average-upload.csv"
do_create_average

TITLE="SFTP Client Upload Speeds [$NUMBER_RUNS runs]"
COMPARE_TO="$PWD/openssh-average-upload.csv"
AVERAGE_FILE="$PWD/wolfssh-average-upload.csv"
OUTPUT_FILE="$PWD/upload-results.png"
do_create_plot

# create openssh average download if not found
AVERAGE_FILE="$PWD/openssh-average-download.csv"
if [ ! -f "$AVERAGE_FILE" ]; then
    echo "Collecting openssh average download"
    rm -f $LOG_FILE && touch $LOG_FILE
    for run in $(seq 1 $NUMBER_RUNS); do
        printf "Run $run: "
        for i in "${FILE_SIZES[@]}"; do
            tail -c "$i" /dev/urandom > "$TEST_FILE"
            printf "$i," >> $LOG_FILE
            do_openssh_get_test
            printf "\n" >> $LOG_FILE
        done
        printf "done\n"
    done

    do_create_average
    echo ""
fi

# create wolfssh average download
echo "Collecting wolfssh average download"
rm -f $LOG_FILE && touch $LOG_FILE
for run in $(seq 1 $NUMBER_RUNS); do
    printf "Run $run: "
    for i in "${FILE_SIZES[@]}"; do
        tail -c "$i" /dev/urandom > "$TEST_FILE"
        printf "$i," >> $LOG_FILE
        do_wolfssh_get_test
        printf "\n" >> $LOG_FILE
    done
    printf "done\n"
done

# compile and plot the results of average download speeds
AVERAGE_FILE="$PWD/wolfssh-average-download.csv"
do_create_average

TITLE="SFTP Client Download Speeds [$NUMBER_RUNS runs]"
COMPARE_TO="$PWD/openssh-average-download.csv"
AVERAGE_FILE="$PWD/wolfssh-average-download.csv"
OUTPUT_FILE="$PWD/download-results.png"
do_create_plot

rm -rf $TEST_FILE
rm -rf $TEST_FILE-out
