#!/bin/bash

echo -e "
           .,;::::,..      ......      .,:llllc;'.
        .cxdolcccloddl;:looooddooool::xxdlc:::clddl.
       cxo;'',;;;,,,:ododkOOOOOOOOkdxxl:,';;;;,,,:odl:.
                     .,:ccccccccccc:::.
"

############################################################### Housekeeping tasks ######################################################################

org=$1
echo -e "\e[94mOrganisation name: "{$1}" \e[0m"
#read org

domain_name=$2
echo -e "\e[94mRoot domain name: "{$2}" \e[0m"
#read domain_name

CIDRS=$3
echo -e "\e[94mCIDRS entered: "{$3}" \e[0m"

echo -e "\e[92mFirst time running? Making output folder... \e[0m"
if [[ -d output ]]
then
        :
else
        mkdir output
fi
if [[ -d output/$org ]]
then
        echo -e "\e[94mOutput folder for  $org Already exists, adding new stuff\e[0m"
else
        echo -e "\e[94mCreating $org directory in the 'output' folder... \e[0m"
        mkdir output/$org
fi



############################################################### Subdomain enumeration ######################################################################
echo -e "\e[92mIdentifying Subdomains \e[0m"

if [ -n "$3" ]; then
    echo -e " 1 or more CIDR in input, running amass on it"
    amass intel -cidr $CIDRS -o all.txtls
else
    echo -e "No CIDR in your input, skipping amass on CIDRS"
fi

echo -e "Checking CHAOS"


CheckInChaos=`(wget -q "https://chaos-data.projectdiscovery.io/index.json" && cat index.json | grep $org | grep "URL")`

if [ -n "$CheckInChaos" ] ;then
        echo -e "Organization exists in CHAOS, using CHAOS first \n"
        wget -q "https://chaos-data.projectdiscovery.io/index.json" && cat index.json | grep $org | grep "URL" | sed 's/"URL": "//;s/",//' | while read host do;do wget -q "$host";done && for i in `ls -1 | grep .zip$`;  do unzip -qq $i; done && rm *.zip || true
        cat *.txt >> output/$org/chaos.txtls || true
        rm index.json* || true
        cat output/$org/chaos.txtls >> all.txtls || true
        echo -e "\e[36mChaos count: \e[32m$(cat output/$org/chaos.txtls | sort | uniq | wc -l)\e[0m"
        find . | grep .txt | sed 's/.txt//g' | cut -d "/" -f2 | grep  '\.' >> subfinder.domains
        ./subfinder -dL subfinder.domains --silent -recursive >> output/$org/subfinder.txtls
        rm subfinder.domains
        cat output/$org/subfinder.txtls >> all.txtls

        echo -e "Running amass on the ip of the hostname you submitted to find more tlds\n"
        MainIp=`(resolveip -s $domain_name)`
        amass intel -active -addr $MainIp >> all.txtls

        rm *.txt
else
        echo -e "Organization doesnt exist in CHAOS, starting subfinder first\n"
        ./subfinder -d $domain_name --silent >> output/$org/subfinder.txtls

        echo -e "Running amass on the ip of the hostname you submitted to find more tlds\n"
        MainIp=`(resolveip -s $domain_name)`
        amass intel -active -addr $MainIp >> all.txtls


        cat output/$org/subfinder.txtls >> all.txtls
fi



############ Generating Wordlist  ##############
cat all.txtls | cut -d "." -f1 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f2 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f3 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f4 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f5 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f6 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f7 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f8 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f9 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f10 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f11 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f12 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f13 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f14 >> temp_wordlist.txt
cat all.txtls | cut -d "." -f15 >> temp_wordlist.txt
cat temp_wordlist.txt | sort | uniq | sed '/^$/d' | sed 's/\*\.//g' | grep -v " " | grep -v "@" | grep -v "*" | sort -u >> $org-wordlist.txt

rm temp_wordlist.txt
mv $org-wordlist.txt output/$org

registrant=$(whois $domain_name | grep "Registrant Organization" | cut -d ":" -f2 | xargs| sed 's/,/%2C/g' | sed 's/ /+/g'| egrep -v '(*Whois*|*whois*|*WHOIS*|*domains*|*DOMAINS*|*Domains*|*domain*|*DOMAIN*|*Domain*|*proxy*|*Proxy*|*PROXY*|*PRIVACY*|*privacy*|*Privacy*|*REDACTED*|*redacted*|*Redacted*|*DNStination*|*WhoisGuard*|*Protected*|*protected*|*PROTECTED*)')
if [ -z "$registrant" ]
then
        curl -s "https://crt.sh/?q="$domain_name"&output=json" | jq -r ".[].name_value" | sed 's/*.//g' | sort | uniq > output/$org/whois.txtls
else
        curl -s "https://crt.sh/?q="$registrant"" | grep -P -i '<TD>([a-zA-Z]+(\.[a-zA-Z]+)+)</TD>' | sed -e 's/^[ \t]*//' | cut -d ">" -f2 | cut -d "<" -f1 | sort | uniq > output/$org/whois.txtls
        curl -s "https://crt.sh/?q="$domain_name"&output=json" | jq -r ".[].name_value" | sed 's/*.//g' | sort | uniq >> output/$org/whois.txtls
fi

registrant2=$(whois $domain_name | grep "Registrant Organisation" | cut -d ":" -f2 | xargs| sed 's/,/%2C/g' | sed 's/ /+/g'| egrep -v '(*Whois*|*whois*|*WHOIS*|*domains*|*DOMAINS*|*Domains*|*domain*|*DOMAIN*|*Domain*|*proxy*|*Proxy*|*PROXY*|*PRIVACY*|*privacy*|*Privacy*|*REDACTED*|*redacted*|*Redacted*|*DNStination*|*WhoisGuard*|*Protected*|*protected*|*PROTECTED*)')
if [ -z "$registrant2" ]
then
        curl -s "https://crt.sh/?q="$domain_name"&output=json" | jq -r ".[].name_value" | sed 's/*.//g' | sort | uniq > output/$org/whois2.txtls
else
        curl -s "https://crt.sh/?q="$registrant2"" | grep -a -P -i '<TD>([a-zA-Z]+(\.[a-zA-Z]+)+)</TD>' | sed -e 's/^[ \t]*//' | cut -d ">" -f2 | cut -d "<" -f1 | sort | uniq > output/$org/whois2.txtls
        curl -s "https://crt.sh/?q="$domain_name"&output=json" | jq -r ".[].name_value" | sed 's/*.//g' | sort | uniq >> output/$org/whois2.txtls
fi

cat output/$org/whois*.txtls >> all.txtls

echo -e "\e[36mCertificate search count: \e[32m$(cat output/$org/whois.txtls | sort | uniq | wc -l)\e[0m"

################ Sublist3r #######################

python3 Sublist3r/sublist3r.py -d $domain_name -o sublister_output.txt &> /dev/null
if [[ -e sublister_output.txt ]]
then
        cat sublister_output.txt >> output/$org/sublister.txtls
        rm sublister_output.txt
else
        :
fi
cat output/$org/sublister.txtls >> all.txtls
echo -e "\e[36mSublister count: \e[32m$(cat output/$org/sublister.txtls | sort | uniq | wc -l)\e[0m"

################ finddomain-linux #######################

./findomain-linux -t $domain_name -q >> output/$org/findomain.txtls
cat output/$org/findomain.txtls >> all.txtls
echo -e "\e[36mFindomain count: \e[32m$(cat output/$org/findomain.txtls | sort | uniq | wc -l)\e[0m"

################ Run Subfinder on  newly discovered tld's #######################

python tld.py | grep -v "Match" | grep "\S" | sort | uniq >> rootdomain.txtls

#cat  all.txtls | awk -F\. '{print $(NF-1) FS $NF}' | sort | uniq >> rootdomain.txtls
./subfinder -dL rootdomain.txtls --silent >> output/$org/subfinder2.txtls
echo -e "\e[36mSubfinder count: \e[32m$(cat output/$org/subfinder2.txtls | sort | uniq | wc -l)\e[0m"
cat output/$org/subfinder2.txtls | grep "/" | cut -d "/" -f3 >> all.txtls
cat output/$org/subfinder2.txtls | grep -v "/" >> all.txtls


mv rootdomain.txtls output/$org/

############################################################################# Starting Alt DNS  ##################################################################

python3 altdns/altdns -i $org.master -o $org.altdnsoutput -w altdns/words.txt -r -s $org.altdns_temp -d 8.8.8.8
cut -f1 -d":" $org.altdns_temp > output/$org/$org.altdns_clean

cat output/$org/$org.altdns_clean >> all.txtls

echo -e "\e[36mAltDns count: \e[32m$(cat output/$org/$org.altdns_clean | sort | uniq | wc -l)\e[0m"


############################################################################# Finalizing And Comparing Master and log File  ##################################################################

echo "www.$domain_name" >> all.txtls
echo "$domain_name" >> all.txtls
cat all.txtls | sort | uniq | grep -v "*." > $org.master


if [[ -e "output/$org/$org.master" ]]; then
    ##diff stuff here if output/$org/$org.master exists
    MastersDiff=`(grep -Fxvf output/$org/$org.master $org.master)`
    if [[ "$MastersDiff" = *[!\ ]*  ]]; then
        ##If the diff had results, show us whats different in the new file, append to output/$org/$org.master
        echo -e "\e[93mNew subdomains found: \e[32mCheck The Log File!\e[0m"
	echo "$MastersDiff"
        echo  "$MastersDiff" >> output/$org/$org.master

        echo -e "[+++] $(date) --- New Subs found for this run" >> output/$org/$org.log
        echo "$MastersDiff" >> output/$org/$org.log

    else
        echo -e "\e[93mNo New Subs found\e[0m"
	echo -e "[---] $(date) --- No new subs found" >> output/$org/$org.log
    fi
else
    ##$org.master doesnt exist, so there's nothing to diff
    cp $org.master output/$org/$org.master
    echo -e "Couldn't find $org.master"
    echo -e "[+++] $(date) --- First Running for "$2"\n" >> output/$org/$org.log
    cat output/$org/$org.master >> output/$org/$org.log


fi

sed -i 's/<br>/\n/g' output/$org/$org.master
rm all.txtls
rm $org.master

############################################################################# Nmap and Eyewitness  ##################################################################

echo -e "\e[93mRunning Nmap on all found domains, then running Eyewitness: \e[32m\e[0m"

nmap -iL output/$org/$org.master -oX output/$org/$org.nmap.xml -oG output/$org/$org.nmap.grp -oN output/$org/$org.nmap.normal

runDate=`(date --iso-8601)`
./EyeWitness/Python/EyeWitness.py --web -x output/$org/$org.nmap.xml -d output/$org/$org.Screens.$runDate --no-prompt --prepend-https --threads 2

########################################################################Final things #############################
echo -e "\e[93mTotal unique subdomains found: \e[32m$(cat output/$org/$org.master  | wc -l)\e[0m"
echo -e "\e[93mTotal unique root domains found: \e[32m$(cat output/$org/rootdomain.txtls  | wc -l)\e[0m"
echo -e "\e[93mTotal NEW unique subdomains found: \e[32m$(echo "$MastersDiff"  | wc -l)\e[0m"
echo -e "\e[93mNew subdomains found:\n\e[32m$(echo "$MastersDiff" )\e[0m"
