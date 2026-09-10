#! /bin/bash

DIR="/tmp/HealthCheck"

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
            break;
        ;;
    esac
}


teamsConnector() {
    MESSAGE=$2
    WEBHOOKURL=
    ADAPTIVECARD=
}

slackConnector() {
    APPID=
    CLIENTID=
    CLIENTSECRET=
    SIGNINGSECRET=
    MESSAGE=$2
    WEBHOOKURL="${SLACK_WEBHOOK_URL:?Set SLACK_WEBHOOK_URL in environment}"
    ADAPTIVEBLOCK=

   
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

    ARRAY=()

    ROOT_PART=$(df -P / | awk 'NR==2 {print $1}')
    AVECOLUMN=$(check_for_error df -h "$ROOT_PART" | awk 'NR > 1 {print $5}')
    AVECOLUMN=${AVECOLUMN%\%} 
    

    if [[ "$AVECOLUMN" -lt 90 ]]; then
        echo "Over 90"
    fi


    # read pings 

    while read p; do
        ARRAY+=("$p")
    done < ip.txt

    
    
    for index in ${!ARRAY[@]}; do
        echo $index/${#ARRAY[@]}
        echo "${ARRAY[index]}"
        check_ping "${ARRAY[index]}" # > stdout.txt 2> stderr.txt
    done

    #patternsdrop
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


    # Rules for firewall

    IPTABLES=$(check_for_error sudo iptables -L | sudo tee -a "$DIR"/iptables.txt)

    connector $1 "$DIR"/iptables.txt $SENDEREMAIL $RECEIVEREMAIL

    NFTTABLES=$(check_for_error sudo nft list ruleset | sudo tee -a "$DIR"/nfttables.txt)

    connector $1 "$DIR"/nfttables.txt $SENDEREMAIL $RECEIVEREMAIL

    FIREWALLD=$(check_for_error sudo firewall-cmd --list-all-zones | sudo tee -a "$DIR"/FIREWALLD.txt)

    connector $1 "$DIR"/FIREWALLD.txt $SENDEREMAIL $RECEIVEREMAIL

   # ss -lntu Checking the ports of opening.

   PORTSSS=$( check_for_error ss -lntu | sudo tee -a "$DIR"/ports.txt)

   connector $1 "$DIR"/ports.txt $SENDEREMAIL $RECEIVEREMAIL

   VMSTATISTICS=$(check_for_error vmstat -w | sudo tee -a "$DIR"/vmstatistics.txt)

   connector $1 "$DIR"/vmstatistics.txt $SENDEREMAIL $RECEIVEREMAIL


    return 0;
}

main