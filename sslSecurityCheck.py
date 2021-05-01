from ssl import PROTOCOL_TLSv1
from datetime import datetime
from OpenSSL import SSL
import requests
import argparse
import socket
import pprint
import json
import time
import ssl

apiURL= 'https://api.ssllabs.com/api/v3/'
apiCALL = ['analyze','getEndpointData']


hostInformation= {'domainInfo':{
    'hostname':'',
    'ipAddress':'',
    'certificateInfo':{},
    'vulnerability':{}}}

def sslCertCheck(domain, port, timeout=None):
    try:
        socketSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socketConn= socket.create_connection((domain,port), timeout=timeout)
        sslContext= ssl.create_default_context()
        sslSocket= sslContext.wrap_socket(socketConn, server_hostname=domain)
        responseData = sslSocket.getpeercert()

        socketSocket.connect((domain, port))
        sslContext = SSL.Context(PROTOCOL_TLSv1)
        sslConn = SSL.Connection(sslContext, socketSocket)
        sslConn.set_tlsext_host_name(domain.encode())
        sslConn.set_connect_state()
        sslConn.do_handshake()
        certificateData = sslConn.get_peer_certificate()
        certSubject = certificateData.get_subject()

        hostInformation['domainInfo']['hostname']= domain
        hostInformation['domainInfo']['certificateInfo']['organization']= certSubject.O
        hostInformation['domainInfo']['certificateInfo']['certificateAlgorithm']= certificateData.get_signature_algorithm().decode()
        hostInformation['domainInfo']['certificateInfo']['certificateVersion']= certificateData.get_version()
        hostInformation['domainInfo']['certificateInfo']['certificateDateFrom']= datetime.strptime(certificateData.get_notBefore().decode('ascii'),'%Y%m%d%H%M%SZ').strftime('%Y-%m-%d')
        hostInformation['domainInfo']['certificateInfo']['certificateDateTO']= datetime.strptime(certificateData.get_notAfter().decode('ascii'),'%Y%m%d%H%M%SZ').strftime('%Y-%m-%d')
        hostInformation['domainInfo']['certificateInfo']['certExpireDay'] = (datetime.strptime(hostInformation['domainInfo']['certificateInfo']['certificateDateTO'],'%Y-%m-%d') - datetime.now()).days

        firstCALL(apiURL,apiCALL, domain)
        return responseData
    except ConnectionResetError or ConnectionRefusedError or ssl.SSLCertVerificationError:
        print(f'SSL Sertifikası bulunamadı veya Sunucuya Bağlanılamamaktadır {domain} \n')
    except TimeoutError or socket.timeout:
        print(f'Sunucuya ulaşılamadı {domain}')


def firstCALL(apiURL, apiCALL, domain):
    apiAnalyz= apiURL+ apiCALL[0]+'?host='+ domain
    print('\nSSL Güvenliği analiz ediliyor... (Biraz zaman alabilir.)')

    #READY, IN_PROGRESS(--), DNS(2)
    while True:
        analyzeDomain= json.loads(requests.get(apiAnalyz).content.decode('utf-8'))
        if analyzeDomain['status'] == 'READY':
            hostInformation['domainInfo']['hostname']= analyzeDomain['host']
            hostInformation['domainInfo']['ipAddress']= analyzeDomain['endpoints'][0]['ipAddress']
            domainIP= analyzeDomain['endpoints'][0]['ipAddress']
            secondCALL(apiURL,apiCALL,domain,domainIP)
            break
        elif analyzeDomain['status'] in ('DNS', 'IN_PROGRESS'):
            #print('SSL Güvenliği analiz ediliyor...')
            time.sleep(10)
            continue

def secondCALL(apiURL, apiCALL, domain, domainIP):
    apiEndpoint= apiURL+ apiCALL[1]+'?host='+ domain +'&s=' +domainIP
    endpointData= json.loads(requests.get(apiEndpoint).content.decode('utf-8'))

    hostInformation['domainInfo']['vulnerability']['heartbleed']= endpointData['details']['heartbleed']
    hostInformation['domainInfo']['vulnerability']['heartbeat']= endpointData['details']['heartbeat']
    hostInformation['domainInfo']['vulnerability']['poodle']= endpointData['details']['poodle']
    hostInformation['domainInfo']['vulnerability']['freak']= endpointData['details']['freak']
    hostInformation['domainInfo']['vulnerability']['logjam']= endpointData['details']['logjam']
    hostInformation['domainInfo']['vulnerability']['drown']= endpointData['details']['drownVulnerable']
    hostInformation['domainInfo']['vulnerability']['beast']= endpointData['details']['vulnBeast']

    hostInformation['domainInfo']['vulnerability']['openSslCcs']= 'True' if endpointData['details']['openSslCcs']== 3 else 'False'
    hostInformation['domainInfo']['vulnerability']['ticketbleed']= 'True' if endpointData['details']['ticketbleed']== 2 else 'False'
    hostInformation['domainInfo']['vulnerability']['zombiePoodle']= 'True' if endpointData['details']['zombiePoodle']== 2 else 'False'
    hostInformation['domainInfo']['vulnerability']['sleepingPoodle']= 'True' if endpointData['details']['sleepingPoodle']== 10 else 'False'
    hostInformation['domainInfo']['vulnerability']['goldenDoodle']= 'True' if endpointData['details']['goldenDoodle']== 4 else 'False'
    hostInformation['domainInfo']['vulnerability']['zeroLengthPadding']= 'True' if endpointData['details']['zeroLengthPaddingOracle']== 6 else 'False'

    hostInformation['domainInfo']['certificateInfo']['tlsVersion']= endpointData['details']['protocols']
    hostInformation['domainInfo']['certificateInfo']['certificateId']= endpointData['details']['certChains'][0]['certIds']

    pprint.pprint(hostInformation)

argParse = argparse.ArgumentParser(description='SSL Güvenliğini kontrol et.')
argParse.add_argument('-d','--domain', help='Domain\'i ver.')
argParse.add_argument('-f','--file', help='URL listesini ver.')
parseAllArgument= vars(argParse.parse_args())

oneDomain= parseAllArgument['domain']
fileRead= parseAllArgument['file']

firstCALL(apiURL, apiCALL, oneDomain) if bool(oneDomain)==True else 'False'

if bool(fileRead)==True:
    allDomain = [domainList.rstrip('\n') for domainList in open(fileRead).readlines()]
    for domain in allDomain:
        sslCertCheck(domain, 443, 5)