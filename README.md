# MEGAPhone
OpenWRT "MegaPhone"

[![megphone](https://media3.giphy.com/media/SjR2HvaFokmJ1a30wR/giphy.gif?cid=790b76118b756c5f14be941a26a5938b51a8b090754c534e&rid=giphy.gif&ct=g)](https://www.youtube.com/watch?v=aAHUNgoJQPw)


# What is this?
It's a MegaPhone for a WiFi Interface that supports RadioTap in Monitor Mode. It captures any beacons around the place, remembers them in memory, and then plays them back.

# Why?
It's particularly useful if you have wifi cards on OpenWRT with a tx/rx chains. Eg you could have a directional antenna on TX but an omni on RX. Essentially what you get is a WiFi version of a Megaphone! Not really useful in practice, but it's a good example of how to (not) 'relay' packets with libpcap.

# Compile?
You'll need the OpenWRT Toolchain. Something like this will work:

```
mips-openwrt-linux-gcc -lpcap -O3 megaphone.c -o megaphone
```
