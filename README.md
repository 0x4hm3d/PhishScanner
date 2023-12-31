![image](https://github.com/0x4hm3d/PhishScanner/assets/81084776/c7fee512-e075-4d61-904b-cf7b46af0135)

# PhishScanner
[![Python](https://img.shields.io/badge/Python-3.x-yellow.svg)](https://www.python.org/) 
![Version 1.0](http://img.shields.io/badge/version-v1.0-orange.svg) ![License](https://img.shields.io/badge/license-MIT-red.svg) <img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f"> 

## Purpose
PhishScanner is a Python script designed to aid in the detection of phishing websites. It performs various checks on suspected URLs to identify potential threats. The script incorporates multiple checks, namely:
- Shortened URL Check
- Tracking IP Domain Check
- Redirection Check
- Google Safe Browsing Database Check
- Whois Lookup
- Real-Time Screenshot

Moreover, it utilizes the APIs of <a href="https://www.virustotal.com/gui/join-us">virustotal.com</a>, <a href="https://urlscan.io/docs/api/">urlscan.io</a> and <a href="https://www.abuseipdb.com/api">abuseipdb</a> to enhance its functionality.
Nevertheless, it's worth noting that you need to specify the corresponding API keys to use the API Key Integration feature.

## Demonstration
[![asciicast](https://asciinema.org/a/63VZyWfCWpm3K3cKoegKRyLsj.svg)](https://asciinema.org/a/63VZyWfCWpm3K3cKoegKRyLsj)

## Installation & Usage
PhishScanner is a cross-platform script that works with Python **3.x**.
```
git clone https://github.com/0x4hm3d/PhishScanner.git
cd ./PhishScanner
pip3 install -r requirements.txt
```
Then you can run it
```
python3.x PhishScanner.py -u url [-f config.ini] [-v]
```

## Important Notes
1. You don't need administrator privileges to run this script.
2. Though you can run this script without specifying <a href="https://www.virustotal.com/gui/join-us">virustotal.com</a>, <a href="https://urlscan.io/docs/api/">urlscan.io</a> and <a href="https://www.abuseipdb.com/api">abuseipdb</a>'s API keys, it is recommended to use them in order to obtain more specific information concerning the suspected URL. To get the API keys, you need to create an account.
3. The APIs used by the script have a limited rate.
<table>
  <tr>
    <td> API </td>
    <td> Rate Limits</td>
  </tr>
  <tr>
    <td> Virustotal </td>
    <td> The Public API is limited to 500 requests per day and a rate of 4 requests per minute </td>
  </tr>
  <tr>
    <td> Urlscan.io </td>
    <td> Unlisted Scans are limited to 1000	requests per day and 60 requests per minute</td>
  </tr>
  <tr>
    <td> AbuseIPDB </td>
    <td> All free accounts have a rate limit of 1000 reports and checks per day</td>
  </tr>
</table>

## API Key Configuration
After downloading the repository and getting your API Keys, you need to configure the config.ini file before executing the script. Here is how to do that:
```
cd ./PhishScanner
cd config
```
Then, you need to edit the config.ini file. Feel free to use your favorite text editor. In my case, I will use nano
```
vim config.ini
```
<img width="1512" alt="image" src="https://github.com/0x4hm3d/PhishScanner/assets/81084776/d1825f7c-cc78-4f9c-aef6-e77dae2f24e5">

#### Warning⚠️: Do not put the API key between double quotes, only copy and paste it!

After properly configuring the API keys, you should be able to get more information using the -f/--file option followed by the config.ini file.
```
python3.x PhishScanner.py -u url -f config.ini -v
```

## Contribution
1. If you noticed any bugs, thanks to reporting <a href="https://github.com/0x4hm3d/PhishScanner/issues">here</a> 
