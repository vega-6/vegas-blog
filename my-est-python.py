import requests
import urllib3
import json
import pandas
import re
from getpass import getpass

#letiltja a hibaüzenetet a self-signed cert bejelentkezésnél, csak tesztelésre ajánlott
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#változók
username = "<felhasznalonev>"
password = "<jelszo>"
file_path = "<excel_file_helye>"
ip_coloumn = "IP address"
est_url = "<est_url>"
est_username = "<est_onboard_user>"
est_password = "<est_onboard_jelszo>"
est_enroll_prof_name = "est-enroll-prof"
est_cert_name = "est-cert"
est_root_cert_name = "est-root"
est_root_cert = """<root_ca_base_64_ben>"""

#rest api session létrehozása
session_api = requests.session()

#IP címek beolvasása egy excelből
def get_ip_list_from_excel(file_path, column_name):
    df = pandas.read_excel(file_path)
    return df[column_name].dropna().tolist()

#API belépés
def api_login(switch_ip):
    creds = {
        "username": {username},
        "password": {password}
        }
    try:
        #belépés rest api-n keresztül
        login = session_api.post(f"https://{switch_ip}/rest/v10.13/login", data=creds, verify=False)
        #login hívás status kód kiíratása, ha 200-as akkor jó
        if login.status_code == 200:
            print(f"A belépés sikeres a {switch_ip} IP című switch-re!")
            return
        else:
            print(f"Sikeretelen belépés a {switch_ip} IP című switch-re! Hibakód: {login.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[{switch_ip}] ⚠️ Hiba a kapcsolódás során: {e}")

#lekérdezzük a switch hosztnevét, mert ez lesz az est tanúsítvány common-name értéke
def get_switch_hostname(session, base_url):
    api_response = session.get(f"{base_url}/system")
    return api_response.json()['hostname']

#lekérdezzük a mgmt port státuszát, ha be van állítva a mgmt port, 
# akkor feltételezzük ezen keresztül kommunikál az EST szerverrel, ha a mgmt port-nak van IP címe és UP státuszban van
# akkor az est profilban a mgmt vrf-et állítjuk be, ha nincs beállítva a mgmt port, akkor pedig a default vrf-fet,
# de ebben a függvényben csak egy True vagy False értéket adunk vissza
def get_mgmt_port_data(session, base_url):
    api_response = session.get(f"{base_url}/system")
    mgmt_config = api_response.json().get('mgmt_intf_status', {})
    has_ip = 'ip' in mgmt_config
    link_is_up = mgmt_config.get('link_state') == "up"
    if has_ip & link_is_up:
        return True
    else:
        return False

#legkérdezzük a meglévő profilokat, és kezeljük, hogy azonos néven már ne próbálja meg létrehozni újra
def check_and_create_profile(session, base_url, api_url, profile_name, profile_data):
    prof_name = profile_name
    get_profiles = session.get(f"{base_url}/system/{api_url}", verify=False)

    if get_profiles.status_code == 200:
        try:
            profiles = get_profiles.json()
            if prof_name in profiles:
                print(f"A(z) {prof_name} profil már létezik!")
                return
            else:
                print(f"A profil még nem létezik, létrehozása folyamatban!")
        except ValueError:
            print("Hibás JSON válasz")
    else:
        print(f"Nem sikerült lekérdezni a profilokat! Hibakód: {get_profiles.status_code}")

    prof_data = profile_data
    response = session.post(f"{base_url}/system/{api_url}", data=json.dumps(prof_data), verify=False)

    if response.status_code in [200,201,204]:
        print(f"A(z) {prof_name} sikeresen létrehozva.")
    else:
        print(f"Hiba történt a profil létrehozásakor, hibakód: {response.status_code}")


#létrehozzuk a ta_profile-t, enélkül nem lehet feltölteni semmilyen kliens certet    
def create_ta_profile():
    ta_profile_data = {
        "name": est_root_cert_name,
        "certificate": est_root_cert
    }
    check_and_create_profile(session_api,base_url_api,"pki_ta_profiles",est_root_cert_name,ta_profile_data)

#est onboard profil létrehozása
def create_est_onboard_prof():
    #itt hívjuk meg a függvényt, ami a mgmt port státuszát vizsgálja, 
    # ha igaz akkor mgmt vrf, ha hamis akkor pedig default vrf lesz beállítva az est enroll profilban
    if get_mgmt_port_data(session_api,base_url_api) == True:
        est_vrf = "/rest/v10.13/system/vrfs/mgmt"
    else:
        est_vrf = "/rest/v10.13/system/vrfs/default"
    
    est_profile_data = {
        "name": est_enroll_prof_name,
        "url": est_url,
        "vrf": est_vrf,
        "username": est_username,
        "password": est_password
    }
    check_and_create_profile(session_api,base_url_api,"pki_est_profiles",est_enroll_prof_name,est_profile_data)
    

#cert létrehozása, meghatározva a common-nevet, amit lekérdeztünk korábban, kulcs típust és az est profilt megadva
def create_est_cert():
    est_cert_data = {
        "name": est_cert_name,
        "common_name": get_switch_hostname(session_api, base_url_api),
        "key_type": "ECDSA-256",
        "est_profile": "/rest/v10.13/system/pki_est_profiles/est-enroll-prof"
    }
    check_and_create_profile(session_api,base_url_api,"pki_x509_certificates",est_cert_name,est_cert_data)

#radsec kliens tanúsítvány beállítása az EST által generált tanúsítványra
def set_radsec_cert(session,base_url):
    radsec_cert = {
        "certificate_association": 
        {
            "radsec-client": est_cert_name
        }
    }
    session.patch(f"{base_url}/system", data=json.dumps(radsec_cert), verify=False)

#kilépés az api session-ből
def api_logout(switch_ip):
    logout = session_api.post(f"https://{switch_ip}/rest/v10.13/logout")
    if logout.status_code == 200:
        print(f"A kijelentkezés sikeres a {switch_ip} IP című switch-ről!")
        return
    else:
        print(f"Sikeretelen kijelentkezés a {switch_ip} IP című switch-ről! Hibakód: {logout.status_code}")
        return

#sorrendben meghívjük a függvényeket és megadjuk a bemenő paramétereket
#kiolvassa az IP címeket és beleírja az ip_list változóba
ip_list = get_ip_list_from_excel(file_path,ip_coloumn)
#a kiolvasott IP címeken egyesével végig megy és mindegyiken lefuttatja a függvényeket
for switch_ips in ip_list:
    base_url_api = f"https://{switch_ips}/rest/v10.13"
    api_login(switch_ips)
    create_ta_profile()
    create_est_onboard_prof()
    create_est_cert()
    set_radsec_cert(session_api,base_url_api)
    api_logout(switch_ips)
    print("--------------------------------------------------------------")
