# SecureAndAsyncP2P

Custom secure implementation based on SHA256RSA 
Digital signature algorithm over TCP communication

### Recommended requirements:
##### jdk 9+
##### 2 cores / 4 threads @ 2.6 GHz CPU with 3MB cache
##### 16 GB RAM

### Usage:
##### First compile:
`cd src`

`javac com\oleksa\Main.java`
##### then start server:
`java com.oleksa.Main server localhost 4444`
##### or client:
`java com.oleksa.Main client remotehost 4444`
