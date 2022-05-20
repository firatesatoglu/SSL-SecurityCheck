# SSL-SecurityCheck
Check Your SSL Cert Vuln with python code

Usage;

	python3 sslSecurityCheck.py -f domainlist.txt
	python3 sslSecurityCheck.py -d badssl.com
	
-h, --help  show this help message and exit

	-d  Just give domain addr and it search for you
	-f  Just give Domain List
 
Output:
```
{'domainInfo': {'certificateInfo': {'certificateId': ['e4abf7001dcf9beec855f2e57214c1ec70c69d311a8e56450b6bbfc0bec313f1',
                                                      '67add1166b020ae61b8f5fc96813c04c2aa589960796865572a3c7e737613dfd',
                                                      '6d99fb265eb1c5b3744765fcbc648f3cd8e1bffafdc4c2f99b9d47cf7ff1c24f'],
                                    'tlsVersion': [{'id': 769,
                                                    'name': 'TLS',
                                                    'version': '1.0'},
                                                   {'id': 770,
                                                    'name': 'TLS',
                                                    'version': '1.1'},
                                                   {'id': 771,
                                                    'name': 'TLS',
                                                    'version': '1.2'}]},
                'hostname': 'badssl.com',
                'ipAddress': '104.154.89.105',
                'vulnerability': {'beast': True,
                                  'drown': False,
                                  'freak': True,
                                  'goldenDoodle': 'True',
                                  'heartbeat': True,
                                  'heartbleed': False,
                                  'logjam': False,
                                  'openSslCcs': 'True',
                                  'poodle': False,
                                  'sleepingPoodle': 'False',
                                  'ticketbleed': 'True',
                                  'zeroLengthPadding': 'False',
                                  'zombiePoodle': 'True'}}}
```
