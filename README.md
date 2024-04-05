# lain_loader


mcs -out:laincoder.exe laincoder.cs

Encrypt shellcode to a file. You're going to need to put the csharp shellcode in yourself. 

mcs -out:lainloader.exe lainloader.cs

Use this to grab the file and decrypt/load it.

You'll also need to add the csharp shellcode to laincoder in the "new byte" section, as well as change the web server IP/filepath in the lainloader file.

**To Do**
  - Behavioral Analysis Evasion. Perhaps split the payload into multiple parts? Put in some benign operations... It only gets detected by EDR after running though. Hm...
  - Atom Bombing or Process Doppelganging, maybe direct memory manipulation.
