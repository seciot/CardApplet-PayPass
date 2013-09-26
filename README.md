CardApplet-PayPass
==================

Javacard Applet for functioning paypass credential


Dependencies
============
This package requires the SimplyTapp STSE libraries to build and simulate with your project.
please find them at www.simplytapp.com free of charge


About
=====
The javacard code included will answer to any reader that requests MasterCard PayPass contactless cards.  


Personalization Script for simulator or gpjNG
=============================================
#card manager
/card
auth

#change the keys to the security domain
put-key -m add 1/1/DES/ffffffffffffffffffffffffffffffff 1/3/DES/ffffffffffffffffffffffffffffffff 1/3/DES/ffffffffffffffffffffffffffffffff

#delete applets if they are already there
delete -r a0000000041010
delete -r 325041592e5359532e4444463031

install -i 325041592e5359532e4444463031 -q C9#() 636f6d2e7374 5070736532506179
#
#c9 = 01-VER(KMC) 541312ffffff-KMC(ID) A86A3D06CAE7046A106358D5B8239CBE-KD(PERSO) 89AA7F00-CSN
#
install -i a0000000041010 -q C9#(01541312ffffffa86a3d06cae7046a106358d5b8239cbe89aa7f00) 636f6d2e7374 50617950617373

/select a0000000041010
#perso store data command...see official paypass notes on formatting.
/send 84E2A000AB01017F9F6C020001563E42353431333132333435363738343830305E535550504C4945442F4E4F545E303930363130313333303030333333303030323232323230303031313131309F6401039F62060000003800009F630600000000E0E09F6502000E9F66020E709F6B135413123456784800D09061019000990000000F9F670103A0010B00004000000000778099D3A002105229A2B1820F3213CAF2243CB19C5DF7DE65E29F48C7F212
/atr

Test transaction script
=======================
#start
/atr
#select PPSE
/select 325041592e5359532e4444463031
#select MC AID
/select a0000000041010
#GPO
/send 80A8000002830000
#read record
/send 00b2010c00
#compute cryptographic checksum
/send 802a8e80040000089900


Exporting
=========
the card applet should be exported to a jar file.  the jar file should be exported from the project and should 
be uploaded to the simplytapp server with the card agent jar file.


 