# ravm 

Web extension to perform remote attestation on an trusted execution secure virtual machine.

## Build

Simply `npm run build` or better `npm run watch` 

### Prerequisites

Tested with: 
* npm 8.13.0
* Node.js  v17.4.0

For Development 
* http-server (https://www.npmjs.com/package/http-server)
* web-ext (https://github.com/mozilla/web-ext)

## Develop

To start the local development instance:

## Web server (https://transparent-vm.net:8080)
* Enable local resolve to transparent-vm.ne (e.g., by adding to /etc/hosts `127.0.0.1 transparent-vm.net`) 
* Please not the private key for https certificate is not included in the repository 
* Run `http-server -C cert.pem  -K key.pem -S` in `demo-site`

## Interactive development 

* `npm run watch`
* In `dist` execute `web-ext run`

## Configure the firefox instance

Add the certificate for the server as an exception 
* Preferences -> Privacy & Security -> Certificates -> View Certificates
* In the Certificate Manager select Servers and use Add Exception... to add https://transparent-vm.net:8080 

Enable permissions of the ravm web-extension
* Preferences -> Extensions & Themes -> Extensions 
* Select check-vm --> Permissions and enable `Access your data for all websites` 
