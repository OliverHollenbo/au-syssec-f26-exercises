# Exercises: Transport Layer Security

## Preliminaries

We do not require any new dependencies for this exercise beyond what was installed in the last exercise. Make sure to have Wireshark and `mitmproxy` installed in your VM in bridged mode.

**Observation**: If your VM is not working you can also install Wireshark and `mitmproxy` in your own host machine. In that case, replace referrences to IP address `192.168.1/2.Z` with `192.168.1/2.Y` as per the diagram below.
There are also some hints and troubleshooting information [in this page](hints.md). Make sure to check it if you have problems or if you are running a native enrivonment without support to virtualization (such as an ARM-based Mac). 

### Network Layout and Preparation

This time the network will be simpler than the previous one, but will follow the same general layout, depicted below.

As previously, there are two wireless networks (`NETSEC` and `SYSSEC`), and the wired network is on subnetwork `192.168.3.0/24`.
Now the Access Point (AP) serves as the _router_ between the wireless and the wired network.
The Web server runs on a Raspberry Pi in the wired network, with IP addresses in the range `192.168.3.2-69`, and abstracts a machine running on the Internet, to/from which traffic is routed by intermediate nodes.

![image](./network-layout.png)

Pick an IP address `192.168.3.W` in the range `192.168.3.2-69`.
Connect to one of the wireless networks using the host system (you know the password) and test that you can connect to `http://192.168.3.W/` using a Web browser.
The traffic between your browser and the server is now being routed by the AP with manually inserted static routes.

Start the VM and make sure that you can `ping 192.168.3.W` and access the HTTP address above in the VM, so you verify that the interface is functional in bridged mode.

## Exercise 1: Malicious-in-the-middle against HTTP in proxy mode

Connect a mobile device to the wireless network and take note of its address `192.168.1/2.X`, referred from here on as *victim*.
You can find the IP address of your mobile device by looking into the network configurations.
In the VM, type `ifconfig` or `ip a` in a terminal and take note of its IP address `192.168.1/2.Z`

**Observation**: If you do not have a mobile device available, ask a colleague to be the client or use the host machine as the victim.

We will run `mitmproxy` in the VM to be able to perform some processing of the captured traffic. Run `mitmproxy` in _proxy_ mode (notice that we need it to accept the self-signed certificate from the Web server):

```
$ mitmproxy --ssl-insecure --showhost
```

In your *victim* device, manually configure your VM as the proxy. You need to supply the address `192.168.1/2.Z` and port 8080 in the configuration.
If everything is working correctly, you should try again to access the Web server `http://192.168.3.W/` in your *victim* device and start seeing captured _flows_ in the `mitmproxy` window.
In this window, you can select a flow by using the arrows and pressing ENTER, while pressing the letter `q` goes back to the overview screen.
Access the Login page in the *victim*, enter some credentials and observe that they are visible in `mitmproxy` as part of an `HTTP POST` method.
You will also notice errors about HTTPS connections not being established, ignore those for now.

Before you proceed to the next exercise, visit the page `http://mitm.it` in your *victim* device. This will allow you to download the self-signed certificate under which `mitmproxy` signs a certificate for each server it impersonates.
Download the certificate, but do not install it yet.

## Exercise 2: Malicious-in-the-middle against HTTPS

Now try accessing `https://192.168.3.W/` in your *victim* device.
You should get another warning about a non-trusted certificate! Inspect the certificate and check that it is suspicious indeed. :)
After accepting the new certificate, you should be able to access the website normally.
Make sure you access the Login page again and that captured credentials are still visible.

Finally, install the `mitmproxy` certificate you downloaded previously in your *victim* device.
On Android, this can be done in the *Encryption & credentials* or *Certificates* part of the configuration, under the *Install a certificate from storage* option.
This will remove any warnings about untrusted self-signed certificates for any of the web servers in the `192.168.3.0` subnet.

## Exercise 3: Malicious-in-the-middle against HTTPS in transparent mode

Change the network configuration of your *victim* device manually to _remove_ the proxy and customize the router. On Android, this means changing the `IP Settings` to `Static`.
Use the same `192.168.1/2.X` as before as the IP address, `192.168.1/2.Z` as the Gateway/DNS and `255.255.255.0` as the network mask.

**Observation**: If you are not running the VM or a Linux environment, you need to translate the configuration below to your own setup. Check [the hints](hints.md) for the latest notes on how to achieve that.

In the VM, let's change the configuration for traffic to be forwarded.
The following configurations need to be performed to enable IP forwarding such that the VM can forward IPv4 traffic while avoiding ICMP redirects:

```
$ sudo sysctl -w net.ipv4.ip_forward=1
$ sudo sysctl -w net.ipv4.conf.all.send_redirects=0
```

Now configure the `iptables` firewall to send all HTTP traffic captured at ports `80` and `443` in the VM to port `8080` under control of `mitmproxy`:

```
$ sudo iptables -A FORWARD --in-interface <interface> -j ACCEPT
$ sudo iptables -t nat -A PREROUTING -i <interface> -p tcp --dport 80 -j REDIRECT --to-port 8080
$ sudo iptables -t nat -A PREROUTING -i <interface> -p tcp --dport 443 -j REDIRECT --to-port 8080
```

Now run `mitmproxy` in _transparent_ mode.

```
$ mitmproxy --ssl-insecure --mode transparent --showhost
```

After that, `mitmproxy` should again receive all HTTPS traffic from your *victim* device, so try accessing the Login page at `https://192.168.3.W/` and check that the credentials show up in a `POST` flow after they are submitted.
If you are running `mitmproxy` in your host system directly (without a VM), make the same configurations above in your host machine firewall.

**Observation**: If you **cannot** see flows in `mitmproxy`, try running the command below in the VM to bypass [a problem with the VirtualBox driver](https://security.stackexchange.com/questions/197453/mitm-using-arp-spoofing-with-kali-linux-running-on-virtualbox-with-bridged-wifi):

```
sudo arpspoof -i <interface> -t <victim> 192.168.3.W
```

## BONUS: Manipulate traffic in mitmproxy

**Note**: This part of the exercise was changed recently and not widely tested across multiple browsers/platforms.

Let's use the scripting capability of `mitmproxy` to mount an _active_ attack.
Our simple website has a login capability, for which the credentials are `admin`/`admin`.

Now access the website through your *victim* device with the right credentials and login. You should now be able to access the `View Secrets` and `Upload Secrets` functionalities.
The `View Secrets` functionality will just show you some secret text, which should be visible in `mitmproxy` as well.
The `Upload Secrets` functionality is more interesting and allows the user to encrypt a message provided in the text field under a public key returned by the server.
The website has been improved from last week to include client-side Javascript, so one can just type the intended plaintext to be encrypted.

Your final task is to _replace_ that public key with a key pair for which you know the private key (to be able to decrypt).
The code for the server portion is provided for reference in the repository inside the folder `simple-website`.

In order to achieve your goal, generate an RSA key pair in PEM format and insert the public key marked as TODO in the file `simple-website/mitm_pk.py`.
You can generate the key pair by running the following commands:

```
$ openssl genrsa -out private.pem 2048
$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

Now restart `mitmproxy` with the command below:

```
$ mitmproxy --ssl-insecure --mode transparent --showhost -s mitm_pk.py
```

Recover the message from the encryption provided by the client. The `rsa-decrypt.py` file in this repository contains the basic code.
