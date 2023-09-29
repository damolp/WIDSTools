# WIDS Tools
OpenWRT "WIDS" Tools


# Tools 
|tool name|function|
|---|---|
|MEGAPhone|Replays beacons. Useful for amplifying beacons or faking RSSI/coverage|
|quickscope|Super quick beacon scanner. Faster than wash in monitor mode|


## MegaPhone
[![megaphone](https://media3.giphy.com/media/SjR2HvaFokmJ1a30wR/giphy.gif)](https://www.youtube.com/watch?v=aAHUNgoJQPw)
This is a MegaPhone for a WiFi Interface that supports RadioTap in Monitor Mode. It captures any beacons around the place, remembers them in memory, and then plays them back.

It's particularly useful if you have wifi cards on OpenWRT with a tx/rx chains. Eg you could have a directional antenna on TX but an omni on RX. Essentially what you get is a WiFi version of a Megaphone! Not really useful in practice, but it's a good example of how to (not) 'relay' packets with libpcap.



## QuickScope
![quickscope](https://media3.giphy.com/media/nFFYKpX4RNPfqorOvd/giphy.gif)
This is a quick way of scanning all 2.4GHz and 5GHz channels. It takes roughly 23 seconds for 2.4GHz and 41 seconds for 5GHz.

Each channel is scanned for 1 second, and with most beacon intervals being 100ms this gives the scanner the chance to see the AP 10 times while listening on the channel.

The output is JSON similar to wash.


# Compiling?
You'll need the OpenWRT Toolchain. Something like this will work:

```
mips-openwrt-linux-gcc -lpcap -O3 megaphone.c -o megaphone
mipsel-openwrt-linux-musl-gcc -lnl-3 -lnl-genl-3 -lpcap quickscope.c -o quickscope -O3
```
