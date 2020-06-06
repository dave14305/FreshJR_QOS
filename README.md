# FreshJR QOS - Modification Script for AdaptiveQOS on ASUS Routers

This script has been tested on ASUS RT-AC68U, running ASUSWRT-Merlin 384.18, using Adaptive QoS with Manual Bandwidth Settings

## Quick Overview:

-- Script Changes Unidentified Packet QOS destination from "Default" Traffic Container (Category7) into user definable (in WebUI) "Others" Traffic Container

-- Script Changes Minimum Guaranteed Bandwidth per QOS category to user defined percentages for upload and download.

-- Script allows for custom QOS rules

-- Script allows for redirection of existing identified traffic

## Full Overview:

See <a href="https://www.snbforums.com/threads/release-freshjr-adaptive-qos-improvements-custom-rules-and-inner-workings.36836/" rel="nofollow">SmallNetBuilder</a> for more information & discussion

## Installation:

In your SSH Client:

``` curl "https://raw.githubusercontent.com/dave14305/FreshJR_QOS/master/FreshJR_QOS.sh" -o /jffs/scripts/FreshJR_QOS --create-dirs && sh /jffs/scripts/FreshJR_QOS -install ```

## Uninstall:

In your SSH Client:

``` /jffs/scripts/FreshJR_QOS -uninstall ```
