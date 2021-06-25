# CPacketParser

A RADIUS parser written using C++ and PcapPlusPlus (wrapper for C-DPDK). 
It extracts attributes from the RADIUS layer.


## High Level Overview

Following diagram depicts the high level flow of the application.
![Arch](https://i.imgur.com/DlxZztN.jpg)

The program starts and 
1. initializes the EAL params
2. setups and starts dpdk devices (ports)
3. Spawn workerThreads

Each workerThread

1. receives a burst on the port
2. loops through the packet burst
3. for each packet burst 
    i. checks packet type
    ii. checks for radius Accounting type
    iii. parses header
    iv. parser Attribute Value Pairs (AVPs)
    v. writes to CSV
    vi. frees the packet
    vii. receives the next burst and so on


## Extracted Information

The parser looks for following port numbers associate with authentication 
and authorization:

```c
AUTHENTICATION PORT 1812 
AUTHORIZATION PORT 1813
```

The minimum lenght of Radius packet required is `230`


### Header

From the header following information is extracted

1. Radius Type
2. Message id
3. Radius Attribute Count

The CPacketParser parses message of the type `ACCOUNTING REQUEST` with is
identifiable by the code `4`.

### Extracted Attribute Value Pairs

The total number of attributes that are looked for are `4`. Following are
the attributes:


1. Framed IPv4 Address
   - Signifies the IPv4 address assigned to the user

2. Framed IPv6 Prefix
   - Signifies the IPv6 prefix assigned to the user

3. Calling Station ID
   - Signifies the calling station identity of the user (either MSISDN, MAC or any other identifier)

4. Accounting Status Type
   - Start; indicating new connection and start of data flow
   - Stop; indicating termination connection and end of data flow
   - Update; indicating updated connection information and  start of data flow with new information

## Algo for extracting AVPs


The AVPs in RADIUS differ in lenght and location and type. Which is why
we have to loop through all the AVPs to get the ones required.

All the AVPs have three parts: 

1. Code
    - Unique Identifier for the Attribute

2. Length
    - the complete length of the AVP

3. Value
    - The data is signified in the next `lenght - 2` bytes.

The data bytes in RADIUS layer are read as follows:

```bash
starting bytes: --- 28 06 00 00 00 02 --- 
28 = dec(28) = 40 (Acct-Status-Type) 
06 = total length 
00 00 00 02 = value =  2 (stop) 
bytes for data (4) are calculated  as follows: 
[total:6] - [bytesforlength:1] - [bytesforcode:1] = 4  
```

---

