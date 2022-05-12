# Casos-de-Uso-Splunk 

## Ataques de fuerza bruta: T1110
host="DC-01" EventCode="4625" Nombre_de_cuenta="*" Estado=0xC000006D "Dirección de red de origen"!="127.0.0.1" | top limit=20 Nombre_de_cuenta,"Dirección de red de origen", _time | timechart count by "Dirección de red de origen"


![brute-force](https://user-images.githubusercontent.com/66162160/167991316-f08af3b4-b45b-4d61-a36e-7e4dce79a901.png)



## Pass The Hash: T1550.002
host="DC-01" ( EventCode=4624) OR ( EventCode=4625) Nombre_de_cuenta="ANONYMOUS LOGON" "Paquete de autenticación"="NTLM" "Dirección de red de origen"!="-" | top "Dirección de red de origen", _time | timechart count by "Dirección de red de origen"


![pass-the-hash](https://user-images.githubusercontent.com/66162160/167991322-9ddcd073-1e7e-4290-8fe6-851b9e6c7738.png)



## Reconocimiento de Active Directory (AD) | BloodHound: TA0007
EventCode="4799" Nombre_de_cuenta="*" | top limit=20 Nombre_de_cuenta, _time | timechart count by Nombre_de_cuenta

![sharphound-BloodHound](https://user-images.githubusercontent.com/66162160/167991331-6e8ef22d-a220-4b82-b06e-392d14874770.png)
