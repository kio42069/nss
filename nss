subject are users
objects are resources

whther subjects can acceess objects is dependent on the clerance level
cant r/w from lower to higher clearance level

pehle the heirarchy was decided by a human admin which was L nuh uh
os ka kaam bare;y tha

then came unix
virt memory came in W 
ab only issue is resource ko dhang ka r/w access dena das it
like user-resource relation bhi karna hota but yeah

no issue occurs even if mutiple processes access the same file cos they load in the file to virt memory 
input mediation - specify kya fomrat for input and which format for putput
dac-  discretuinary access control 
dlls dynamic linkied libraries
shared memory ka usage ^^
like some stadnanrd c liub
after the process using the dll is done it id noone else is usinvgv it then the page eviction ago will yeet it off

in the old mcus like 8086 ()intel and 8088 (ibm) there wasnt a flat memory adress space so they had DOS to handle that 
x86 ^^
no protection, can just access any memory 

flat memory model -> har processor ko lagta it has the entire memory to itself, so irl it cant access the actual entire memory in any way (super safe)
earlier they just had hardocded machine lang to allocate meory but since no OS to check or hardware supporting paging so multiple processes could ealsiy access memory being used by other process
ok but abhi tak chip mein encryption not ecnrypted, just the flat memory thign and a paging thing
 higher end firewalls charge for per unit or r=encryptin and decrypitng speeds smth

sticky bit?? equivalent to dirty bit ye toh dekhna hoga
uid instead of string cos 1) stroing ints >> storing strings 2) matching uids easier, if wanna match strings need another lib ew no bugs 


setuid lets the process become the actual owner of the program
passwds stores in /etc/passwd .etc/shadows 
can check the actual uid for checking who ran the command originally
geteuid() -> gives the actual owner
getuid() -> gives the guy who ran

if as root u once give up the privilege then u cant get it back again (in a single run)
alag users ke liye kitne baar bhi lo do doesnt matter
this is cos the system wants to limit its expsure to u 

acl's in windows == dacs in unix



=============================================
lecture 3: 

if same user, then user's rwx bits are checked before running
if the user belongs to the same group, then gid, 
if not even that, then the others rwx is used

vfs - virtual fs - jaisa tree dikhta hai fs ka, thats not how its actully stored 

when we wanna mount a ntfs to ext4, what we do is create a module where we define empty functions pointing to functions like open read write 
everytime i wanna open or write smth to the ntfs now i just call the function which points to the related code writable to ntfs

kernel modules are pieces of code (.ko, not .o on compilation) which can read the kernel space 

pehle if new device, have to recompile the kernel, now you have kernel modules which can be loaded into the kernel 
so the module registers the required system calls for the appropriate file operations called 


in the kernel code of linux, u import a header file 
in that header we hav e struct containing the file operations 
with void functions 
insmod -> function to load in a module 
inode ??

  open(path)
  |
  |
  ------ kernel space
  software interrupt
  |
  |
  syscall interrupt handler() {
    fv.open = &my-open()
  }

  now my-open checks for permissions and runs wtv 

in ntfs no concept of perms, as ntfs is not designed for vfs, so to remove permissions u can copy a file to ntfs and copy it back 
ACL's are also stored with a file, but its structure is different from the xxx-xxx-xxx structure
??? so what happens to the ACL if we copy smth to ntfs from a linux like fs 


getfacl, setfacl for setting ACLs in linux


how tf does the password mech work, smth related to hashes but system still does not seem scure 

DACs work over ACL, so is DACs dont let a user to do smth, then ACLs cant do anything
MAC's precede over DACs (machine level accesl control list)

in case of multiple groups, just use the mask , which is logically anded with all the group perms and decide based on that 


l2 firewalls -> switch level firewall (super basic) allows macs 
l3 deices -> routers at ip level

ppi boxes -> application level firewalls

ncfw
net config firewall
transproxy


==========================================
lrecture 4 : jan 16, thu

firewalls -> network access controls


network --- firewall --- edge router --- outside 

firewall has a network address translator (public to private ip convertion)

inwards nat (dNAT) -> public ip to private nat convertion for data flow 
outward nar (external sNAT [source nat]) -> private ot public ip, jab kuch bahar data bhejna hota

first 1024 ports are perma inpe services chalti
ephemereal port numbers - 30k to 50k, 55k ~ 

diff bw firewalls and acls is that acls are contextless
old fws were stateless fws 
stateful are where u note where the data (which ip) it came from  
syn ack 
source nat. dest nat, and a binat -> bideirectional nat 


N2 : 192.168.3.7  
N1 : 192.168.7.33 -> 22.23.44.56/24

pehle n2 se nikalte huye snat use hoga, then n1 mein jaake dnat use hoga, this is essentially a binat 
binat changes the course addy too, while a dnat only changes the destination addy 
so in a binat, if installed on a fw, the destination would feel the data came from the firewall (vpn mein use hota)
ddos attacks mein out of state packets bhejte (to prevent, firewalls just discard the packets)
reflective dos?
amazon if it sees that too many syn packets without any syn acks then itll simply block the packtes 
open dns resolvers dhundho pehle like 1.1.1.1 or 8.8.8.8 (google and cloudflare)
ya fir kuch kisine misconfig se galti se open chhod diya 
isps ke khudke dns resolvers hote hain 
the reason why isps dont do acess control on dns resolver is cos of roaming -> if airtel ki range se bahar gaye, u can simply latch onto a jio tower (unke aapas mein deals hain, each pays the other)
home location registrar 
diff country ^^ jaate toh u tell ur indian isp, they will deal with the local isp, and give ur moeny to em 
in case of a diff country / isp they ask for an auth token / sign which is presented by ur phone, if ok then u get network access 
if valid token only then, tower pe hi check ho jaata 

so in reflective dos, the attacker crafts a raw packet with source addy that of the victim, spams it to dns server, and now the firewall cant know, so it just replies everything to the victim
dns server par firewall hota cos it can simply allow an inward connection to the dns serivce, if cna run many other serivces with vulnerabilities but now it doesnt matter cos its safe (koi access hi ni kar sakta)
reuqest x 10 = response
ngfw - next gen firewall (multi job forewall)
active directory, netbios -> domain authentication -> u might be given a home directory after ur authenticated at the acitve directory end 
kurberos server??


dmz server  and firewall 
to prevent the server being exploited to access the LAN, use time boudn tokens

issues with proxy -> slow & protocol specific & cant do end to end encryption 

tls

=========================================
MISSED A LECTURE (ANUJ GROVER AAAAAAAAAA)
=========================================
Lecture 6??
routing mein longest prefix match hota 
192.168.1.10/24   <- dest add 
_________
longest prefix is matched and uspe bhejte hain (routing decision)
0.0.0.0 <- every ip is matched

prerouting hook, and at the end a post routing hook 
snat changes source addy 
masquerade -> many ips leave with same source address 

firewalls do first rule match, whichever rule macthes first, wahi ue ho jata hai
DROP -> silently drop a packet (attacker doesnt know we are up or not, no reply, confusion)
RESET -> tell the sender that we are up and running, exists to say that we are up, but this port is blocked.
^
|
security via confusion 

evtables -> mac filtering
nftables combines evtables with iptables
iptables and nftables wagera are applications which instruct the firewal via kernel 
advantage of combining them?? why is nftables better than iptables? cos kernel is singlethreaded
ip = ipv4
ip6 = ipv6
inet = tcp/ip 
arp bridge 

all this in context for nftables, jiska command is `nft`
can set priority of the rulsets too 
family??
chains??
neg priority >>> positive prioirty in the tables

firewall blocking means connectino scannot be initiated, requests and html wagera toh allowed 

pf == iptables but for freebsd / openbsd
pf means packetfilter
only one hook, no complex prerouting blah blah

add hooks to heads, they are points where firewalling can happen
hook has a function

bsd : sysctl.conf -> iske andar ek flg hota sysctl net.inet.ip.forwarding=1 set it to 1 to allow
linux : /proc/sys/net/ipv4/ipforward

by default block all incoming, allow all outgoing
block in all 
pass out all keep state    ----------------------------------------------------
keep stat emeans statefull                                                    |
                                                                              |
udp is stateless, firewalls will drop it, so we need a tcp dns   --------------
udp dns is prefeered for lowe asf overhead in comparison to tcp dns
browser first tries udp, if it doesnt work then it tries tcp
ab toh it specifically allows the dns requests cos yeah (speicifically udp port 53)
pop3 -> email
pop -> ssl

udp keep state means for dns requests , protocol doesnt allo wit but it sends it regardless, mostly used in network firewall, not a user firewall. ,helps in matching dns query with dns response
cann do this with specific network interfaces too
the () brackets in ext+if means do a NAT
port grouping, can specifiy ports, protocols too

flags S/SA -> syn / syn ack, bas inhi ke liye state rakho
jaise FIN ke liye state rakhne ki zaroorat nahin 


ATTACKER 
reconnaisance karta pehle
1. passive recon
  get info like subdomains, ppl, employees
  bade saare tools hain to automate fetching subdomains -> theharvester
  also tells all email ids, using different search engines
  attacker doesnt do it, someone else does it, so it looks like normal google searches
  abhi open port finding nahin karte hain
  ip addresses for all the domains
  sublister -> similar, python imple, while harvester is in go
  checker whtehr they are suing valid certs or not, may be inactive domain, uska cert expire ho chuka hoga, crt.sh se milta hai, hamara tool khud karke bata deta hai
  smart ppl will add in decoys, keeping u busy
  honeypots

  next up, identify open services, port scan -> open tcp and udp ports
  lecture 7???
  tool -> nmap | zmap
  zmap faster, inaccurate
  nmap slower, accurate asf
  nmap best
  nmap relies on crafting raw sockets, and analyses the reponses and reports em
  if it finds port 443 open, it will try to do a tls handshake and get all info about the homepage of the site wagera

  nmap -A -p -T4 ip
  T4 means speed of the search, faster search will give u the data fas, but ppl will be alerted too

  nmap also has a thing called OS fingerprinting
  tells you what is the host os, helps u understand what kind of vulns may be present, helps u decide attack vectors, compromise vectors

  after identifying a web service, 
  dirbuster (java based) - creates multiple tcp udp connections and tries to brute force directories like index.html blah blah
  can provide a word list too, for directories , for files
  a web service is like a remote directory access
  gobuster

  nikto, similar to dirbuster or dirb (cli)
  after getting the taregt hostname, gets versions for stufff like apache webserver, modules etc. are they vuln or not, what are their numbers 

  site called expoit-db
  searchsploit - cli tool
  searches for exploits for specific versions of webservers
  usually RCE
  the exploit usually tellss u what input to give to do a buffer overflow

  netcat -> craft html requests and send em
  privilege escalation->run instructions of a user higher than u, 

========================================================= 
lecture 7 !!!!!!!!!!!!!

virtbox better ? ok will try it 

active cert means the website is active
certificate has a common name
can check domain name with owner name, if same then shai bande ki website hai
if domain down, cert will be gone (probably, not zaroori)

domain enumeration tools
sublist3r
censys -> passive recon version for zmap, they have servers which simply run zmap for u 
shudan
~ 18 such scanners, called benign scanners

on ur site, robots.txt. if wahan we mention, some of them will not scan u

if u wanna hide ur ip from getting scanned, just hide it in plain sight
how? use honeypots, by making the scanners think that the main site is a decoy, cos when they send requests to the honeypots, they will just think oh lol decoy imma not try to use this
MIITRE attack framework

buffer overflow attacks

bss -> static vars, which are only allocated in stack once
heap -> dynamic memory 
ro data-> consts and strings in quotes

gcc ke options sikhne, stop it after assembly ban jaye etc.

=========================================================================

lecture 8 !_?
read material regarding x86 and x86_64 

PRF -> pseudo random func, but cantbe done irl 
prp -> psudo random permuation , close to the prf 

the code book

ceaser cipher
vigenere cipher 
enigma and colosus machine 
the imitation game - alan turing, to crack the enigma machine 
enigma was just an electronic vigenere cipher machine
vernam cipher - one time pad 
stream cipher ^^ 
used in mobile communication whcih are lossy, as some bits after corruption can be regenerated again 
but issue is key length == message length, so videos wagera ke liye not feasible
so, a seed, feed it to a prng, p meaning pseudo

homomorphic 
m1 xor k1 = c1
m2 xor k1 = c2
(c1 + c2) xo3 k1
additive, multiplicative, homomorphic encryption
can just add the encrypted text, and decrypt just the final grade
A6 cryptography used in phone calls
salsa fast
nonce = number used only once 
block cipher, uses prp
crypto accelerator
block ciphers work v well with tcp cos packets are a thing 
round keys
aes 
des - old aes {data encryption stadnanrd}
iv = initialisation vector, or nonce

authentication 

kya tu isliye macro bana raha tha :sob: 

challenge repsonse protocol


==========================================================================

lecture 9 !!!!!!


blacktoolin / blackarch
metasploit mentioned? whats that

stream cipher padhna tha shit 
shannon's perfect secrecy
/dev/random and /dev/urandom
chacha20 and chacha12 
RTP? 
ECB - electronic port(control ig not port) block, used in block ciphers 
chosen ciphertext attack / chosen plaintext attack
CCA and CPA ^^ (so we call it not CCA secured)
issue is every block is not randomised, so ciphertext can repeat 
so we introduce cipher block chaining, CBC
message is first XORed with the initialisation vector (IV or nonce or randomisation vector) 
and we chain this output to the next input 
issue is if one block is corrupted, no way to know that, and subsequent blocks will also get corrupted
one possible solution is to send the hash too, but issue is we can only verify after the entire message is decrypted, also even the hash can get corrupted, also the hash can be replayed during some form of auth.
so, encrypt the hash too
what we do irl is that we take the last block, pass it to another round, and then hash that and send that hash 
AEAD ^^
number of blocks = size / aes128 -> divide by 16

to be even more secure, pass the nonce thru a PRP first to get an IV , need two sets of keys btw, one just for the nonce and one for the message
but only if u dont have a good enough PRNG, usually /dev/urandom is good enough 
but hella slow method, since everything depends on the last block 

nonce counter model
we add 1 to iv for every block and paralellise it,
issue with this is if our data is fkin large, the iv will start repeating, losing out on the desired randomness 
if iv was short enough ^^^ 


oh btw we dont hash entire message cos it can be absolutely humongous, vv computationally intensive



GCM mode (galios counter mode)
for every block of ciphertext you have a nonce -> number osed once, also not IV, IV is v v v random, nonce doesnt need to be random enough 
u pass it thru the nonce thru the aes 
encrypt each block individually
also, nonce is concatenated with a counter
galios hash, ghash, takes a random number, constant H, some additional data, h is multiplied with the additional data 
that is xored with the cipher, which becomes hte addiitional data for the next block, so on 
hash, xor, multiply is supafast
so the chain is fast, encryption which is slow is parallelelsied 
end mein nonce ki jo IV bani thi thats used to create tje signature called auth tag
helps to let us know if even the nonce was tampered with or not 

used in encrypting high quantity file sizes
TEE, trusted execution environment
it runs in ur firmware, only privileged users can write it. it can be used to check if OS is compromised or not
if the TEE hash doesnt match, u cant boot 
secure boot
XTS mode

authenticated encryption with associated data -> AEAD

CCM counter mode with CBC MAC

merkle-damgard construct, HMAC 
looks like CBC, but hash operations, not cipher operations
we just want plaintext with auth, no encryption 

HMAC is a keyed hash
hash(IV xor K xor ipad) xor M[0]
whats ipad and opad?
constant values, in hashing, numbers with far enough hamming distance
hamming? number of bits to flip in A to create B


alibaba cloud service? need chinese id. need chinese id? dedicated id generator for china lol, but good enough just for alibaba

============================================================
lecture 10!!!!!!!!!

who are you
what do you know ---|
                    | ---- this is multi factor auth, u knwo a secret key and some thing like a fingerprint, rfid, whatever 
what do you have ---|
what do u want 

centralised auth - symmetic cipher 
decentralised - asymmetric cipher 
here, ur identity is pulicly announced, but people will come to u and 
chek if what u claim is who u are 
example, https -> not a phishing site 
as it has a digital certificate 
this does not require a central entity
its avail with the public, they just authenticate

most basic one, challenge response protocols
!!!!!!!!!!!!!!! my_sudo -> do input validation, the attacker might try a buffer overflow, so thats a possible vuln !!!!!
wtf is HMAC 
comes from a keyed hash or smth 


use the ciphertext as an iv and reecnrypt the ciphertext 

kdc -> trusted entity, key distri centre 
session key 
k a-b
needham shroeder solution 
who was kerberos lmao suna suna lagra 


active directory attacks? lol

================================================================================

lecture 11 ~~~~~~~~
sudoers check karna hoga assn mein 

in reflection attack, statless algo
u take info from a different session and replay that in another session to gain access 

key discovery attack -> older ticket's key 
solution -> use a new key everytime?

in the needham schroeder, we cant store nonce since its sonly used once

authentication  -> u r who u r 
authorisation   -> u have the perms which u claim to have

TGT -> ticket granting ticket

KTGS -> long term key of the TGS, granted by the KDC 
authenticator info -> unique to the client, like timestamp, this is enc with K_C,TGS


TGS grants a client to server ticket, enc with key of server, which it gets from the KDC 

finally, server does a challenge response 

password isnt sent, its used 

multiple points of failure, if AS, KDC or TGS fail the entire protocol goes down 
C_TGS is incide TGT, encyrpted


in roaming, SSO toh hai hi, so the sim can use that ticket from airtel and give it to jio to authenticate 
thia happens when it senses low network strength, and it gives a token 
the towers can triangulate u and if it senses ur gonna go into enemy territory itll give u the token 
its a signed token which the other guy will respect
jio and airtel has a service layer agreement, SLA.
they have predecided tokens 

what happens if i dissapear, switch off phone for a while and then appear in the enemy territory, how wil it authenticate

inter realm comms ^^

LDAP server , alternate auth to username password
lightweight directory access protocol


==========================================================

lecture 12 ~

ecryptfs -> on top of file system, uske thru encrypt hoke write hota hai , uses aes 
TEE -> trusted execution environment

OpenSSL
|
|- - libssl
|    |
|    |-- TLS
|
|- - libcrypto
|    |
|    |-- crypto permities
|    |
|    |-- block ciphers
|    |
|    |-- ...
|

netcat creates a generic tcp udp client server


ex 2 
part 1  -> play around with ecryptfs and test stuff for report
part 2 -> netcat convo but openssl
bonus -> scp but openssl


unsigned char * kyu? cos 1 extra bit -> 8 bits -> byte array, assembler, treat it like a byte array


figure out what does md6 do, its  aprogram which speeds up md5 hashing, internally it still uses openssl?? but how it so fast

ldap -> lightweight directory access protocol -> this is just a tree 
active directory AKA n/s password -> network services

SMB -> server message group

metasploit
ps -> powershell 
psexec -> windows ke liye ssh, cna use putty.exe which emulates a ssh terminal, but psexec is for powershell 
msfconsole



===============================================
lecture 13 @@@@@@@@@@@@@@@@@@@@@@@@@@22.23


img2pdf
script
ps2pdf


3 vulns, like replaying, reflection 

ldap has modules for 2fa too, public private crypto with certs too 
not only passwords

ad merges kdc and ldap

NTLM hashed passwords -> windows ad thing 
can brute force it, since the password is just sent after being hashed
or can try to replay too 

ntlm is a format, has other stuff too like headers and shit, but basically andar hashed password directly hota, without any nonca or iv 
ad also starts acting like a dns resolver, so if any uri reported which doesnt exist with the ad, then itll multi cast (broadcast to everyone)
haccer can go say oh yeah im the one, gimme password


similar to arp, alice knows bobs ip but she doesnt know how to reach him , so she will ask everyone who has bobs ip, 
charlie can say oh i have and then alice can send to him 
caches exist for mac codes

there is a race condition also, u gotta respond faster than the actual guy who has bobs addy

altho it can be handled in higher layers lmfao


hashcat / john -> cracking hashes 
ntlmreplayx and responder
^
|
requires that messages are not signed, i.e. smb has to be disabled 
cos then only itll be replayable


!!! idea
whatsapp plugin, maybe detect thats whatsapp active, and when u press enter itll copy the text u typed in and encrypt and send it, and when messages comes in usko decrypt karke print 


insecure.org lmao goofy ahh icon

powerview -> lateral movement, finding more vulnerable services once inside a victim
active rocn btw ^^

bloodhound??
crackmapexec

spidering??? spiders??? WIDOWMAKER???
ah brutefrocing directory discovery
--spider IT 

nfs is equivalent of smb i guess? dunno


canonical name is like a nick for a service

kerberosting a

spn mentioned i think it crackes hashes brute force se brute force se 

llmnr what that


mimikatz -> golden ticket attack ??


