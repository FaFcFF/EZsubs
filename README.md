# EZsubs
External enumeration runner... runner. There are many like it, but this one is mine. 

Built for timed use with cron, set it to run every so often, then check back at the log file to see if any new subs were found. 

Alot of this code was (~~straight up stolen~~) heavily inspired by https://github.com/iamthefrogy/frogy

All subs are saved in output/{ORG_NAME}.master

Run logs are saved in output/{ORG_NAME}.log

EyeWitness results are saved in output/{ORG_NAME}.Screens/

Usage: `./EZsubs.sh ORGANIZATION_NAME DOMAIN_NAME CIDR(Optional)`

Example: `./Ezsubs.sh yahoo yahoo.com 74.6.0.0/16` Or: `./EZsubs.sh yahoo yahoo.com`

# What does it do?
  Runs amass, subfinder, findomain, sublister. Then runs altdns, nmap, EyeWitness on those domains. More features will come.... Eventually.... 


# Dependencies:
  python3
  
  jq
  
  amass
  
  subfinder
  
  nmap
  
  sublist3r.py located in Sublist3r/
  
  altdns located in altdns/
  
  Eyewitness located in EyeWitness/Python/
  
  
# To do: 
  -Put all this in docker since installing all these is pretty annoying.
  
  -Bruteforce http endpoints gently to find easy wins. (Like a swagger file or something). Also show it in the log if it 200's
  
  -Add the ability to specifiy what you want to run as arguments, Ex: RunSubfinder=Y RunEyeWitness=N
  
  -Add the ability to only run commands that don't connect to targets at all, if the user chooses.
  
  -Maybe add a normal subdomain bruteforce feature
  
