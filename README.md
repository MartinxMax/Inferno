
# Inferno

`$ ./Install.sh`

![alt text](./Pic/image-1.png)

`$ python Inferno.py -h`

![alt text](./Pic/image-2.png)

## Simulated Server

`$ sudo python3 -m pip install --upgrade cpppo`
`$ python -m cpppo.server.enip SCADA=INT[1000] ADMIN=INT[2] -v`

Create an EtherNet/IP device

![alt text](./Pic/image.png)

## Device Scanning

`$ python Inferno.py -scan 192.168.8.0/24`

![alt text](./Pic/image-3.png)

## Tag Brute-forcing

`$ python Inferno.py -rhost 192.168.8.107 -gtag`

![alt text](./Pic/image-4.png)

## Reading

Index 1:

`$ python Inferno.py -rhost 192.168.8.107 -tag SCADA -read 1`

![alt text](./Pic/image-5.png)

Index 1-20:

`$ python Inferno.py -rhost 192.168.8.107 -tag SCADA -read 1-20`

![alt text](./Pic/image-6.png)

## Writing

Index 1, type INT, value 90:

`$ python Inferno.py -rhost 192.168.8.107 -tag SCADA -write '1:(INT):90'`

![alt text](./Pic/image-7.png)

Index 1-20, type INT, value 55:

`$ python Inferno.py -rhost 192.168.8.107 -tag SCADA -write '1-20:(INT):55'`

![alt text](./Pic/image-8.png)
