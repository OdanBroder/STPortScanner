using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace OnlyExe_STPortScanner
{
    internal class Config
    {
        public static string ConfigDefPorts { get; private set; }
        public static string ConfigProbes { get; private set; }
        public static void Initialize()
        {
            ConfigDefPorts = """
137	netbios-ns
138	netbios-dgm
139	netbios-ssn
""";
ConfigProbes = """
totalwaitms 6000
# If the service closes the connection before 3 seconds, it's probably
# tcpwrapped. Adjust up or down depending on your false-positive rate.
tcpwrappedms 3000

##############################NEXT PROBE##############################
**[PROBE_S]**
PROBE_DATA     [UDP]    {\x80\xf0\0\x10\0\x01\0\0\0\0\0\0\x20\x43\x4bAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0\x21\0\x01}
PROBE_INDEX    [4]
PROBE_PORTS    [137]

# NBTStat queries use DNS query packet format and so will trigger responses from DNS services
# the \x0_, \x8_, \x9_ below accounts for recursion / authenticated data flags
PROBE_REGEX    [domain]    {(?is)^\x80\xf0[\x80\x81][\x02\x82\x92]\0\x01\0\0\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01$}
PROBE_REGEX    [domain]    {(?is)^\x80\xf0[\x80\x81][\x03\x83\x93]\0\x01\0\0\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01$}

PROBE_REGEX    [domain]    {(?is)^\x80\xf0\x81\x83\0\x01\0\0\0\0\0\0 ckaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\0!\0\x01}

# NBT Response starts with a header:
# The following fields are each 2 bytes: transaction ID; Flags; question count; answer count; name service count; additional record count
# Next comes 34 bytes NUL-terminaed name
# then comes 2 byte fields: question type; question clss
# 4 byte TTL
# 2 byte rdata length
# 1 byte number of names
### -- End of header
# Next comes the given number of nbnames - each are a 15 byte name (space padded) followed by a one byte service type, and then 16 BIT flags
### -- End of name table - finally comes the footer:
# 48 - Adapter address (eg MAC addy)
# 8 bit fields: major version; minor version
# 16 bit fields: duration; frmps received; frmps transmitted; iframe receive errors; transmit aborts
# 32 bit fields: trasnmitted; received
# The remaining fields are all 16-bits: iframe transmit errors; number of receive buffers; tl_timeouts; tl_timeouts; free ncbs; ncbs;
#                                       max_ncbs; number of transmit buffers; max datagram; pending sessions; max sessions; packet_sessions

# I'm not convinced that these next 4 work on a very wide variety of
# machines.  I think most of the real matching comes in the next block.
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...(\w{1,15}) *\0\x04\0(\w{1,15}) *\0\x84\0\w{1,15} *\x03\x04\0\w{1,15} *\x04\0\w{1,15} *\x1e\x84\0\w{1,15} *\x1d\x04\0\x01\x02__MSBROWSE__\x02\x01\x84\0(\w{1,15}) *\x03}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...(\w{1,15}) *\0\x04\0(\w{1,15}) *\0\x84\0\w{1,15} *\x03\x04\0\w{1,15} *\x04\0\w{1,15} *\x1e\x84\0\w{1,15} *\x1d\x04\0\x01\x02__MSBROWSE__\x02\x01\x84\0\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...(\w{1,15}) *\0\x04\0(\w{1,15}) *\0\x84\0\w{1,15} *\x03\x04\0\w{1,15} *\x04\0(\w{1,15}) *\x03\x04\0\w{1,15} *\x1e\x84\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...(\w{1,15}) *\0\x04\0(\w{1,15}) *\0\x84\0\w{1,15} *\x03\x04\0\w{1,15} *\x04\0\w{1,15} *\x1e\x84\0}

# It would be really nice if we could get username and/or OS
# information from this.  But it is quite hard to parse out the proper
# information unambiguously, especially with just regular expressions.
# But it certainly would be nice to get more info:
#
# nbtstat
#
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0\0..([\w\-]{1,15}) *\0D\0.*\0([\w\-]{1,15}) *\0\xc4\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0\0..([\w\-]{1,15}) *\0D\0([\w\-]{1,15}) *\0\xc4\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0\0...*\0([\w\-]{1,15}) *\0D\0.*\0([\w\-]{1,15}) *\0\xc4\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0\0...*\0([\w\-]{1,15}) *\0D\0([\w\-]{1,15}) *\0\xc4\0}

# Samba
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15})[\s]{0,14}\x20\x04\0.*?([\w\-]{1,15})[\s]{0,14}\0\x84\0\0\0\0\0\0\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15})[\s]{0,14}\0\x04\0.*?([\w\-]{1,15})[\s]{0,14}\x1e\x84\0\0\0\0\0\0\0}

# The following lines contain very similar matches but allow for variations in ordering of Workstation (\0\x04\0) and Workgroup (\0\x84\0)
# Active Directory Controllers - service \x1c
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15})[\s]{0,14}\0\x04\0.*?[\w\-]{1,15}[\s]{0,14}\0\x84\0.*?([\w\-]{1,15})[\s]{0,14}\x1c\x84\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...[\w\-]{1,15}[\s]{0,14}\0\x84\0.*?([\w\-]{1,15})[\s]{0,14}\0\x04\0.*?([\w\-]{1,15})[\s]{0,14}\x1c\x84\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...[\w\-]{1,15}[\s]{0,14}\0\xc4\0.*?([\w\-]{1,15})[\s]{0,14}\0D\0.*?([\w\-]{1,15})[\s]{0,14}\x1c\xc4\0}

# Member servers, workgroup, etc
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15})[\s]{0,14}\0\x04\0.*?([\w\-]{1,15})[\s]{0,14}\0\x84\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15})[\s]{0,14}\0\x84\0.*?([\w\-]{1,15})[\s]{0,14}\0\x04\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15})[\s]{0,14}\x20\x04\0.*?([\w\-]{1,15})[\s]{0,14}\x1e\x84\0}

# The following allow more flexible ordering of Workstation (\0\x04\0) and Workgroup (\0\x84\0) and the number of other NetBIOS services between
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15})[\s]{0,14}.*\0([\w\-]{1,15})[\s]{0,14}\0\x84\0}

# Apple seems to just include the Workstation service, with the permanent flag. Second matchline accounts for MAC address included in packet
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0\0A\x01([\w\-]{1,15})[\s]{0,14}\0d\0\0\0\0\0\0\0\0\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0\0A\x01([\w\-]{1,15})[\s]{0,14}\0d\0[^\0]{6}\0\0\0\0\0\0\0\0\0}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0\0A\x01([\w\-]{1,15})[\s]{0,14}\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0}

PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15})[\s]{0,14}\0d\0.*\0([\w\-]{1,15})[\s]{0,14}\0\xe4\0}

PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0\0/\x00......\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0}

PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x85\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15}).*\04\0([\w\-]{1,15}) *\x1e\x84\0}


#
# Samba has a version too
# nmbd version 2.2.7 on Linux 2.4.20
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15}).*\0([\w\-]{1,15}) *}

# From an acer PDA
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...\0\x80H'y\x86\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0}

# From a mikrotik router
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x85\x80\0\x01\0\0\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...\d+\.\d+ \0D\0\0\0}

PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\x00\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...\x01\x02__MSBROWSE__\x02\x01\x84\0(MACBOOKPRO-[0-9A-F]{4})\0.*\0([\w._ -]+)\x1d}

PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x85\x80\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]+) *\0\x04\0}
# Brother MFC-9340CDW
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\x04\x93\xe0...([\w-]+)\0D\0......\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0}


PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0\x84\0\0\0\0\x01\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01\0\0\0\0...([\w\-]{1,15})[\s]{0,14}}
PROBE_REGEX    [netbios-ns]    {(?is)^\x80\xf0[\x80-\x8f].\0\0\0.\0\0\0\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01}

PROBE_REGEX    [ntp]    {(?is)^\x04\x01\0\0\0\0\0\0\0\0\0\0LOCL....\0\0\0\0AAAAA\0\0!....\0\0\0\0....\0\0\0\0}

# Apparently used on OS X: http://support.apple.com/kb/ts1629
PROBE_REGEX    [osu-nms]    {(?is)^\x08\x02\0\x03\x03\x11\0\0\x03\x03\x12\0\0\x03\x03\x13\0\0\x03\x03\x14\0\0\x06\x03\x15\0\0\0\0\0\x06\x03\x16\0\0\0\0\0\x03\x03\x18\0\0\x04\x03\x19\0\0\0\x06\x03!\0\0\0\0\0\x06\x03\"\0\0\0\0\0\x06\x03#\0\0\0\0\0\x06\x03\$\0\0\0\0\0\x06\x03%\0\0\0\0\0\x06\x03&\0\0\0\0$}
**[PROBE_E]**
##############################NEXT PROBE##############################
""";
        }
    }
}