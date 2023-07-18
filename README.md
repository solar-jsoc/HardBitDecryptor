# HardBitDecryptor
This program allows you to decrypt files encrypted by HardBit ransomware. 
The program was mainly tested for HardBit3 version 3 but it also works for version 2.

# How to decrypt
There are several options for decryption:
- *-help*	  
  `HardBitDecryptor.exe -help`


  ![hardbit_decr_help_menu](https://github.com/solar-jsoc/HardBitDecryptor/blob/master/images/-help.PNG)


- *-id <client_id str>*	  
   Used as a password to generate an encryption key for the AES CBC algorithm (read more in the article).  
   Specify the *client_id* manually (flag *-id*).  
   If the *-id* flag is not specified, the client_id is generated automatically for the current host.
- *-getid*  
   Get client_id for current host without decryption process.

   ![getid](https://github.com/solar-jsoc/HardBitDecryptor/blob/master/images/-getid.PNG)

- *-all (decrypts all files from all logical disks)*      
   `HardBitDecryptor.exe -id <client_id> -all`  
   or  
   `HardBitDecryptor.exe -all`

    ![image](https://github.com/solar-jsoc/HardBitDecryptor/blob/master/images/-all.PNG)

- *-d <dir_path> (decrypts files from the specified directory)*  
   `HardBitDecryptor.exe -id <client_id> -d <dir_path>`  
   or  
   `HardBitDecryptor.exe -d <dir_path>`
   
  ![dir_decr](https://github.com/solar-jsoc/HardBitDecryptor/blob/master/images/-d.PNG)
 
- *-f <absolute_filename> (decrypts specified file)*   
   `HardBitDecryptor.exe -id <client_id> -f <absolute_filename>`  
  or  
  `HardBitDecryptor.exe -f <absolute_filename>`
  
  ![file_decr](https://github.com/solar-jsoc/HardBitDecryptor/blob/master/images/-f.PNG)

   

*When using the -all/-d flags, a log file is created in the current directory.*

# IMPORTANT!

Encrypted files are not deleted!	
It is recommended to run from the administrator.
