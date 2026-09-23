#! /bin/bash

DIR="/tmp/HealthCheck"

NOTIFYOPTION=$1
SENDEREMAIL=$2
RECEIVEREMAIL=$3

if [[ -d "$DIR" ]]; then
     echo "DIRECTORY /tmp/HealthCheck does exist."
else 
   sudo mkdir /tmp/HealthCheck
fi


check_for_error()
{
    "$@"
    returnC=$?

    if [[ $returnC -eq 0 ]]
    then
        echo "Successfully ran [ $@ ]" >&2
    else
        echo "Error: Command [ $@ ] returned $returnC" >&2
    fi

    return $returnC
}

check_ping()
{
    local target="$1"
    local output
    output=$(ping -c 1 -W 2 "$target" 2>&1)
    local returnC=$?

    if [[ $returnC -ne 0 ]]; then
        echo "Error: ping to $target failed (exit $returnC)" >&2
        echo "$output" >&2
    fi

    return $returnC
}

check_for_file() {
    local base="$1"
    local file1="${base}.txt"
    local file2="${base}2.txt"

    if [[ -e "$file1" && -e "$file2" ]]; then
        local diffOutput
        diffOutput=$(sudo diff "$file1" "$file2")
        if [[ -n "$diffOutput" ]]; then
            echo "$diffOutput" | sudo tee -a "$base"_diff_result.txt
            connector "$NOTIFYOPTION" "Change detected in ${base}:"$'\n'"$diffOutput" "$SENDEREMAIL" "$RECEIVEREMAIL"
        fi
    elif [[ -e "$file1" && ! -e "$file2" ]]; then
        sudo touch "$file2"
    else
        sudo touch "$file1"
    fi

     sudo mv "$file1" "$file2"
}

connector() {
    case $1 in
        "1")
            teamsConnector "$@"
        ;;
        "2")
            slackConnector "$@"
        ;;
        "3")
            sendEmail "$@"
        ;;
        "12")
            teamsConnector "$@"
            slackConnector "$@"
        ;;
        "13")
            teamsConnector "$@"
            sendEmail "$@"
        ;;
        "23")
            slackConnector "$@"
            sendEmail "$@" 
        ;;
        "123")
            teamsConnector "$@"
            slackConnector "$@"
            sendEmail "$@"
        ;;
        *)
            echo "No option notification provided"
        ;;
    esac
}


teamsConnector() {
    MESSAGE=$2
    WEBHOOKURL=#WEBHOOKURL
    ADAPTIVECARD=
}

slackConnector() {
    APPID=
    CLIENTID=
    VERTIFICATIONTOKEN=
    CLIENTSECRET=
    SIGNINGSECRET=
    MESSAGE=$2
    WEBHOOKURL=

    curl -X POST -H 'Content-type: application/json' --data "{\"text\": \"$MESSAGE\"}" #webhookurl
}

sendEmail() {
    sendmail < $2 -f  $3 $4
}

main () {

    # Scan for open ports in the network
    # Send packets to internal IP addresses as well as ublic onces
    # Check internal drive usage (partition)
    # Check Logs for Drops, Rejects, and Unexpected Behavior in the firewall
    # Add a cound of the Drops, Rejects and Errors besides dumping the file entirely
    # Confirm Rule Order and Matching Behavior int he firewall
    # Zone Assignments in the firewall
    # Check   vmstat reports information about processes, memory, paging, block IO, traps, disks and cpu activity.
    # As well check interfaces

    ARRAY=()

    ROOT_PART=$(df -P / | awk 'NR==2 {print $1}')
    AVECOLUMN=$(check_for_error df -h "$ROOT_PART" | awk 'NR > 1 {print $5}')
    AVECOLUMN=${AVECOLUMN%\%} 
    

    if [[ "$AVECOLUMN" -lt 90 ]]; then
        connector 2 "Available space in disk is equal or less than 90%!" $SENDEREMAIL $RECEIVEREMAIL
    fi


    # Read pings 

    while read p; do
        ARRAY+=("$p")
    done < ip.txt

    
    
    for index in ${!ARRAY[@]}; do
        echo $index/${#ARRAY[@]}
        echo "${ARRAY[index]}"
        check_ping "${ARRAY[index]}" # > stdout.txt 2> stderr.txt
    done

    # Patternsdrop

    sudo truncate -s 0 "$DIR"/result_reject.txt
    for file in /var/log/*; do 
        if [ -f "$file" ]; then 
            sudo grep -e "REJECT" "$file" | sudo tee -a "$DIR"/result_reject.txt
        fi 
    done

    sudo truncate -s 0 "$DIR"/result_drop.txt
    for file in /var/log/*; do 
        if [ -f "$file" ]; then 
            sudo grep  -e "DROP" "$file" | sudo tee -a "$DIR"/result_drop.txt
        fi 
    done

    sudo truncate -s 0 "$DIR"/result_error.txt
    for file in /var/log/*; do 
        if [ -f "$file" ]; then 
            sudo grep  -e "ERROR" "$file" | sudo tee -a "$DIR"/result_error.txt
        fi 
    done


    # Rules for firewall IPTABLES and NFTTABLES

    IPTABLES=$(check_for_error sudo iptables -L | sudo tee -a "$DIR"/iptables.txt)

    connector $1  "$(cat "$DIR"/iptables.txt)" $SENDEREMAIL $RECEIVEREMAIL


    NFTTABLES=$(check_for_error sudo nft list ruleset | sudo tee -a "$DIR"/nfttables.txt)

    connector $1  "$(cat "$DIR"/nfttables.txt)" $SENDEREMAIL $RECEIVEREMAIL


    #Getting Firewalld rules and regions
    
    FIREWALLD=$(check_for_error sudo firewall-cmd --list-all-zones | sudo tee -a "$DIR"/FIREWALLD.txt)

    connector $1 "$(cat "$DIR"/FIREWALLD.txt)" $SENDEREMAIL $RECEIVEREMAIL


   # ss -lntu Checking the ports of opening.

   PORTSSS=$( check_for_error ss -lntu | sudo tee -a "$DIR"/ports.txt)

   connector $1 "$(cat "$DIR"/ports.txt)" $SENDEREMAIL $RECEIVEREMAIL


    # VM Statistics 

    VMSTATISTICS=$(check_for_error vmstat -w)
    echo "$SSSUMMARY" | sudo tee "$DIR"/vmstatistics.new > /dev/null
    check_for_file "$DIR"/vmstatistics

    # ss -s summary

    SSSUMMARY=$(check_for_error ss -s)
    echo "$SSSUMMARY" | sudo tee "$DIR"/sssummary.new > /dev/null
    check_for_file "$DIR"/sssummary

    return 0;
}

main