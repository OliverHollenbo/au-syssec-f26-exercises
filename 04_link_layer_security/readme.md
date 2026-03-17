# Exercises: Link Layer Security

**The big picture:**
In this and the following weeks you will be asked to operate multiple environments simultaneously, such as (i) the guest operating system inside the VM, (ii) the host operating system and (iii) a mobile device. If it gets a bit overwhelming or setting up your machine fails for some reason, you can always pair up with a colleague.

## Preliminaries: software installation

You should begin by installing required dependencies. If you are completely new to Wireshark, a nice tutorial for beginners can be found [here](https://www.youtube.com/watch?v=TkCSr30UojM).

**From the following list of Operating Systems (OS), read the part that corresponds to your OS:**
<details>
<summary> Ubuntu 24.04 VM </summary>

```
sudo apt install net-tools aircrack-ng dsniff wireshark
```

Wireshark will ask about users without priviledges being able to capture packets, for which you should answer affirmatively. You should also add your user to the group `wireshark` so that no root priviledges are required for sniffing (after adding your user to a new group, you need to logout and login again for the change to apply).
</details>

<details>
<summary> MacOS </summary>

```
sudo brew install aircrack-ng libpcap libnet
```

You should install Wireshark natively by downloading from the [official website](https://www.wireshark.org/download.html).
Please use this [experimental port](https://github.com/KasperFan/macos-arpspoof) of the `arpspoof` command to Mac OS X.

Please notice that cloning software from a random GitHub repository and running it with root privileges goes against **everything** we teach in this course!
</details>

<details>
<summary> Windows/WSL </summary>

At the time of writing, Wireshark or ARP spoofing do not play well with the WSL virtualized network interface. Install native versions of [Wireshark](https://www.wireshark.org/download.html) and an [ARP spoofer](https://github.com/alandau/arpspoof).

</details>

## Preliminaries: scanning the network - finding the BSSID

There are two access points, with SSIDs `SYSSEC` and `NETSEC`, that you need to find the link layer addresses for.
These two networks have different IP ranges: `192.168.1.0/24` and `192.168.2.0/24`, respectively.
You can find the link layer addresses using your **native** environment by using the commands below.


<details>
<summary> GNU/Linux </summary>

You can discover what your wireless interface is by running one of the commands below:
```
ip link
ifconfig
```

You can scan the wireless networks by running:

```
iwlist <wifi_interface> scan
```

</details>

<details>
<summary> MacOS </summary>

The *deprecated* `airport`command lists the networks
```
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s
```

</details>

<details>
<summary> Windows </summary>

Apparently, you can scan the wireless networks by running the following command *when disconnected*:

```
netsh wlan show networks mode=bssid
```

</details>

## Exercise 1: Dictionary Attack

**The big picture:**\
How do you join a wifi-network without the password? Well, you guess! - and then you keep guessing! \
This is what we call a *brute-force* attack.
But why be **stupid**, when you can be **clever**? \
Use a dictionary of **good guesses** to make it fast!

**The details:**\
The first exercise requires breaking into one of the wireless networks available in the classroom by running a dictionary attack.
Both networks are configured to use WPA2-PSK with a **weak** password.

**What real attackers do:**\
A typical attack starts by placing your network interface in _monitor_ mode, and then capturing traffic from other devices.
For attacking WPA-PSK2, a common approach is to capture the handshake packets when a new device enter the network, or alternatively to force the deauthentication of a device so it connects again and the handshake can be captured.

**The resources at your disposal:**\
Because not all interfaces support monitor mode and this functionality is typically not available in Virtual Machines, we already provide packet captures of the handshake for the two access points in this repository - the files named *syssec-handshake.cap* and *netset-handshake.cap* - and refer interested readers to [a tutorial](https://www.aircrack-ng.org/doku.php?id=cracking_wpa) for more details.

**What you should do:**\
Find a dictionary of common words in English to run the attack, and to discover the link layer address (MAC / BSSID) of the access point.
With these informations, you can then run:

```
aircrack-ng -w <dictionary_file> -b <link_layer_address> <packet_capture>
```

**The goal:**\
You should be able to obtain the correct password after a few minutes of computation.

## Exercise 2: Sniffing the network

**The big picture:**\
Got access to the network? Great - let's abuse it to *sniff* some passwords and wreak some havoc! Or at least let's learn how to do it...

**The details:**\
One immediate consequence of an attacker having access to traffic in plaintext at the link layer is the natural possibility of capturing sensitive data. This is especially dangerous in wireless networks, since essentially anyone within distance has access to the communication channel.

In this exercise, we will observe how sniffing works in practice. We will take the opportunity to assemble and verify a networking environment for the next exercises in the course, so please check your setup carefully.

**Prerequisites:**\
You will need to have the Wireshark tool installed as per the dependencies above.
You will also need to configure your VM network interface to allow all network traffic to be captured inside the VM.

**What to do:**\
In VirtualBox, you have to change the Network Settings such that my Network Adapter was Attached to a Bridged Adapter. In Advanced, I marked Allow All in the Promiscuous Mode to be able to capture traffic from the host environment inside the VM. The screenshot below shows the settings:

![VirtualBox network configuration](vb-network.png)

**RESTART YOUR VM AFTER THIS CHANGE!**

### How to sniff the network - learning to use Wireshark
Think of the Virtual Machine as a malicious machine in a wireless network. Although the scenario is not completely identical to the real world, it should serve the illustration purposes we need here.

1. After the settings are changed (see screenshot), run Wireshark inside the Virtual Machine. You should be able to start a Capture session by clicking directly on the Shark symbol, and all traffic should become immediately visible. Depending on how the network interface driver is [implemented](https://www.virtualbox.org/manual/ch06.html#network_bridged), you might see traffic from the host (your native OS) as well. 

2. We can perform more directed sniffing by restricting to a hostname. The _Options_ item under the _Capture_ menu accepts a capture filter that allows one to specify fine-grained traffic capturing rules - *why would you look at garbage, when you can throw it out?* \
To show how that works, we use the networks SYSSEC and NETSEC, that each run an HTTP server. This server has the following open IP-address ranges: `192.168.1.2--79` (SYSSEC) and `192.168.2.2--79` (NETSET). \
Pick one IP address in the range at random and start a new Wireshark capture with `host 192.168.X.Y` as the capture filter (replace `X` with 1 for SYSSEC or 2 for NETSEC, and replace `Y` with the random value you chose between 2 and 79).

1. Now access the IP address on the VM machine by typing `http://192.168.X.Y/` in your browser, and you should be able to see the plaintext HTTP traffic in Wireshark. If your VM is able to capture traffic from the host, accessing the website from the host will also show traffic in the VM.

## Exercise 3: ARP Spoofing
**The big picture:** \
Finally, it's time to *sniff* some passwords and wreak some havoc - for real!

**The details:**\
We will use a classical ARP Spoofing attack to redirect traffic from a host in the local network to a malicious machine. Traffic redirection is a typical lower-level intermediate step in a higher-level attack such as man-in-the-middle at the network/transport layer. We will play with those in the next weeks, so today we will just focus on the link layer.

1. Setup the VM as instructed in the previous exercise. Notice that this **does not** allow the VM to capture traffic to/from other machines connected in the same local wireless network.

2. Connect a mobile device (smartphone or a friend's computer) to the same wireless network (`SYSSEC` or `NETSEC`) as your host machine is connected to. Take note of your phone's IP address (located within wifi settings) and the server you used previously (`http://192.168.X.Y/`) and start a Wireshark capture within the VM targeting the IP address for the mobile device.

3. Open the address `http://192.168.X.Y/` in your mobile device. You should see the same web page as you saw earlier (the OpenWRT administration page served by the router). If your mobile device has trouble staying in the wireless network without Internet access, try to disable your 3G/4G/5G data connection.

4. Run ARP spoofing to poison the ARP cache of your mobile device (using the `-t` option) so that it sends traffic to the VM instead of the real server. Replace the interface (Linux: `enp0s3`, Mac: `en0`), the victim's IP address (the IP address of your mobile) and the IP address of the server (that you picked randomly) in the command below. Note that the `arpspoof` command takes IP addresses as arguments.


**The command:**
<details>
<summary> Linux / Mac </summary>

```
$ sudo arpspoof -i <interface> -t <victim> <server>
```

</details>


<details>
<summary> Windows </summary>

```
$ arpspoof.exe --oneway <victim> <server>
```

</details>

5. Now generate traffic from the mobile device by logging in with any username/password combination. You should suddenly see the traffic from your mobile in Wireshark.
This can include ARP traffic, TCP retransmission attempts and luckily **an HTTP POST method sending the username/password**. 

6. Try a few times if it does not work at the first time, as there is a race condition between the ARP spoofing responses and the real ARP traffic. If successful, you should see the something similar to the screenshot below. It helps if you load the page, then start the ARP spoofing, and then submit the Login form.

![image](https://user-images.githubusercontent.com/5369810/135161121-8879b20a-8ae0-4bb5-abaa-431015ce3351.png)

**Did you get the password? - if yes: YAY! You're a real hacker! - if not, check the setup in steps 1-4 and retry step 5**
