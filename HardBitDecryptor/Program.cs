
using System.Text;
using System.Security.Cryptography;
using System.Management;
using Microsoft.VisualBasic;
using System.Globalization;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DNGuard
{
    class Program
    {
        static RSACryptoServiceProvider create_rsa_provider_from_b64(string s)
        {
            RSACryptoServiceProvider rsacryptoServiceProvider = new RSACryptoServiceProvider();
            rsacryptoServiceProvider.ImportCspBlob(Convert.FromBase64String(s));
            return rsacryptoServiceProvider;
        }

        static string wmi_select(string mClass, string props)
        {
            StringBuilder sb = new StringBuilder();
            string queryString = "SELECT " + props + " FROM " + mClass;
            string[] props_arr = props.Split(',');

            using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(@"root\CIMV2", queryString))
            {
                using (ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get())
                {
                    foreach (ManagementBaseObject managementBaseObject in managementObjectCollection)
                    {
                        ManagementObject managementObject = (ManagementObject)managementBaseObject;
                        using (managementObject)
                        {
                            for (int i = 0; i < props_arr.Length; i++)
                            {
                                sb.Append(managementObject.GetPropertyValue(props_arr[i]));
                            }
                        }
                    }
                }
            }
            return sb.ToString();
        }

        static string wmi_get_processorId()
        {
            string processorId = string.Empty;

            SelectQuery query = new SelectQuery("Win32_Processor");
            ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(query);

            foreach (ManagementBaseObject managementBaseObject in managementObjectSearcher.Get())
            {
                ManagementObject managementObject = (ManagementObject)managementBaseObject;
                processorId = managementObject["ProcessorId"].ToString();
            }

            return processorId;
        }

        static string wmi_get_product()
        {
            string product = string.Empty;

            SelectQuery query = new SelectQuery("Win32_BaseBoard");
            ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(query);

            foreach (ManagementBaseObject managementBaseObject in managementObjectSearcher.Get())
            {
                ManagementObject managementObject = (ManagementObject)managementBaseObject;
                product = managementObject["Product"].ToString();
            }

            return product;
        }

        static string wmi_get_mac()
        {
            string mac = string.Empty;
            ManagementClass managementClass = new ManagementClass("Win32_NetworkAdapterConfiguration");
            ManagementObjectCollection instances = managementClass.GetInstances();

            foreach (ManagementBaseObject managementBaseObject in instances)
            {
                ManagementObject managementObject = (ManagementObject)managementBaseObject;

                if (mac.Equals(string.Empty))
                {
                    if (Convert.ToBoolean(managementObject.GetPropertyValue("IPEnabled")))
                    {
                        mac = managementObject.GetPropertyValue("MacAddress").ToString();
                    }
                    managementObject.Dispose();
                }

                mac = mac.Replace(":", string.Empty);
            }

            return mac.ToString();
        }

        static string md5(string s)
        {
            using (MD5CryptoServiceProvider md5CryptoServiceProvider = new MD5CryptoServiceProvider())
            {
                return BitConverter.ToString(md5CryptoServiceProvider.ComputeHash(Encoding.ASCII.GetBytes(s))).Replace("-", "");
            }
        }

        static string sha1(string s)
        {
            using (SHA1CryptoServiceProvider sha1CryptoServiceProvider = new SHA1CryptoServiceProvider())
            {
                byte[] array = sha1CryptoServiceProvider.ComputeHash(Encoding.Default.GetBytes(s));
                StringBuilder sb = new StringBuilder();
                int num = array.Count() - 1;

                for (int i = 0; i <= num; i++)
                {
                    byte b = array[i];
                    int low_byte = b & 0xf; 
                    int high_byte = (b >> 4) & 0xf; 

                    if (high_byte > 9)
                    {
                        sb.Append(Strings.ChrW(high_byte - 0xa + 0x41).ToString(CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(high_byte.ToString(CultureInfo.InvariantCulture));
                    }

                    if (low_byte > 9)
                    {
                        sb.Append(Strings.ChrW(low_byte - 0xa + 0x41).ToString(CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(low_byte.ToString(CultureInfo.InvariantCulture));
                    }
                }
                return sb.ToString();
            }
        }

        static int getOffset(FileStream fileStream, int offset_num)
        {
            long length = fileStream.Length;
            fileStream.Seek(-8 * offset_num, SeekOrigin.End);
            byte[] offset_end_file = new byte[8];
            fileStream.Read(offset_end_file, 0, offset_end_file.Length);
            Array.Reverse(offset_end_file);
            StringBuilder hex_length = new StringBuilder(offset_end_file.Length * 2);
            foreach (byte b in offset_end_file)
                hex_length.AppendFormat("{0:x2}", b);
            return int.Parse(hex_length.ToString(), System.Globalization.NumberStyles.HexNumber);

        }


        static string decryptSmallFile(string sourceFile, AesManaged aes)
        {
            FileStream openStream1 = new FileStream(sourceFile, FileMode.Open);
            int int_length_enc_data_begin = getOffset(openStream1, 1);
            int int_length_orig_data = getOffset(openStream1, 3);
            MemoryStream ms = new MemoryStream();
            CryptoStream cryptoStream1 = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Write);
            openStream1.Seek(-40, SeekOrigin.End);
            int name_file_size = openStream1.ReadByte();
            openStream1.Seek(-32, SeekOrigin.End);
            int size_some_data = openStream1.ReadByte();
            openStream1.Seek(int_length_enc_data_begin + size_some_data, SeekOrigin.Begin);

            byte[] array_length_name_file = new byte[name_file_size];
            openStream1.Read(array_length_name_file, 0, name_file_size);
            cryptoStream1.Write(array_length_name_file, 0, name_file_size);
            cryptoStream1.Close();
            byte[] data1 = ms.ToArray();
            var file_name = Path.GetDirectoryName(sourceFile) + "\\" + Encoding.Unicode.GetString(data1);

            openStream1.Seek(0, SeekOrigin.Begin);
            CryptoStream cryptoStream = new CryptoStream(openStream1, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read); 
            FileStream outStream = new FileStream(file_name, FileMode.Create);

            BinaryReader decryptReader = new BinaryReader(cryptoStream);
            byte[] data;
            data = decryptReader.ReadBytes(int_length_orig_data);
            
            outStream.Write(data, 0, data.Length);
            outStream.Close();

            return file_name;
        }
        static string decryptBigFile(string sourceFile, AesManaged aes1)
        {
            FileStream openStream = new FileStream(sourceFile, FileMode.Open);
            int encrypted_data_from_begin_length = getOffset(openStream, 1);
            int orig_bytes_after_begin_offset_len = getOffset(openStream, 2);
            int orig_file_len = getOffset(openStream, 3);
            int encrypted_last_byte_length = getOffset(openStream, 4);
            int enc_filename_len = getOffset(openStream, 5);


            MemoryStream ms = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(ms, aes1.CreateDecryptor(aes1.Key, aes1.IV), CryptoStreamMode.Write);
            openStream.Seek(orig_file_len + 16, SeekOrigin.Begin);

            byte[] array_length_name_file = new byte[enc_filename_len];
            openStream.Read(array_length_name_file, 0, array_length_name_file.Length);
            cryptoStream.Write(array_length_name_file, 0, enc_filename_len);
            cryptoStream.FlushFinalBlock();
            byte[] file_name_array = ms.ToArray();
            var file_name = Path.GetDirectoryName(sourceFile) + "\\" + Encoding.Unicode.GetString(file_name_array);

            CryptoStream cryptoStream1 = new CryptoStream(openStream, aes1.CreateDecryptor(aes1.Key, aes1.IV), CryptoStreamMode.Read);
            openStream.Seek(0, SeekOrigin.Begin);
            BinaryReader decryptReader = new BinaryReader(cryptoStream1);
            byte[] data;
            data = decryptReader.ReadBytes(encrypted_data_from_begin_length - 16);
            cryptoStream1.Close();
            byte[] result_array = new byte[orig_file_len];
            data.CopyTo(result_array, 0);

            openStream.Close();

            FileStream openStream1 = new FileStream(sourceFile, FileMode.Open);
            openStream1.Seek(-40 - orig_bytes_after_begin_offset_len, SeekOrigin.End);
            byte[] array_orig_byte = new byte[orig_bytes_after_begin_offset_len];
            openStream1.Read(array_orig_byte, 0, orig_bytes_after_begin_offset_len);
            array_orig_byte.CopyTo(result_array, data.Length);

            long file_length = new FileInfo(sourceFile).Length;
            if (Math.Max(file_length - encrypted_data_from_begin_length, 0) >= 0x3e800)
            {
                openStream1.Seek(encrypted_data_from_begin_length, SeekOrigin.Begin);
                byte[] unecrypted_blob = new byte[orig_file_len - 2 * 0x3e800 - 0x10];
                openStream1.Read(unecrypted_blob, 0, unecrypted_blob.Length);
                unecrypted_blob.CopyTo(result_array, data.Length + array_orig_byte.Length);


                openStream1.Seek(-40 - orig_bytes_after_begin_offset_len - enc_filename_len - encrypted_last_byte_length, SeekOrigin.End);
                CryptoStream cryptoStream2 = new CryptoStream(openStream1, aes1.CreateDecryptor(aes1.Key, aes1.IV), CryptoStreamMode.Read);
                BinaryReader decryptReader2 = new BinaryReader(cryptoStream2);
                byte[] data2 = decryptReader2.ReadBytes(encrypted_last_byte_length - 0x10);
                data2.CopyTo(result_array, data.Length + array_orig_byte.Length + unecrypted_blob.Length);
            }
            else
            {
                openStream1.Seek(encrypted_data_from_begin_length, SeekOrigin.Begin);
                byte[] unecrypted_blob = new byte[orig_file_len - 0x3e810];
                openStream1.Read(unecrypted_blob, 0, unecrypted_blob.Length);
                unecrypted_blob.CopyTo(result_array, data.Length + array_orig_byte.Length);
            }

            FileStream outStream = new FileStream(file_name, FileMode.Create);
            outStream.Write(result_array, 0, result_array.Length);
            return file_name;
        }     

        static List<string> GetRecursFiles(string start_path, string pattern)
        {
            List<string> ls = new List<string>();
            try
            {

                string[] folders = Directory.GetDirectories(start_path);
                foreach (string folder in folders)
                {
                    ls.Add(folder);
                    ls.AddRange(GetRecursFiles(folder, pattern));
                }

                string[] files = Directory.GetFiles(start_path, pattern);
                foreach (string filename in files)
                {
                    ls.Add(filename);

                }


            }
            catch (System.Exception e)
            {
            }
            return ls;
        }
        static string[] SearchFile(string path, string pattern)
        {
            List<string> encr_files = new List<string>();
            List<string> list_dir = GetRecursFiles(path, pattern);
            foreach (string item in list_dir)
            {
                if (item.Contains(".hardbit"))
                    encr_files.Add(item);
            }


            return encr_files.ToArray();

        }
        static string decryptFiles(string sourceFile, AesManaged aes1)
        {
            long file_length = new FileInfo(sourceFile).Length;
            if (file_length <= 0x3e800)
              return decryptSmallFile(sourceFile, aes1);
            else
              return decryptBigFile(sourceFile, aes1);
        }

        static void ShowHelp()
        {
            Console.WriteLine("\nRECOMMENDED TO RUN AS ADMINISTRATOR!\n\n----Commands----\n-help - show help\n-getid - get client id for current host\n-id <client_id> - input client_id from client_id.txt\n       -f <encrypted_file_absolute_filename> - decrypt one file\n" +
                "       -d <full_path_directory_for_decryption> - decrypt files from a directory (including subdirectories)\n       -all - decrypt all files on the host\n" +
                "Example: HardBitDecryptor.exe -id 097143869C9979E177F25C815046C39C487CA574 -all\n\nIf the -id flag is not present, then the client_id will be automatically generated for the host where the program is running.\nExample:HardBitDecryptor.exe -all");
        }

        public static void DecryptDir(string dir, string client_id)
        {
            string[] path_enc_file_arr = SearchFile(dir, "*.hardbit*");
            if (path_enc_file_arr.Length.Equals(0))
                Console.WriteLine("Files matching the condition were not found! (" + dir + ")");
            using (AesManaged aes = new AesManaged())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.BlockSize = 128;
                aes.KeySize = 256;
                byte[] IV = new byte[] { 0x5c, 0xd2, 0x23, 0x95, 0xee, 0xef, 0x2a, 0x45, 0x25, 0x47, 0xaa, 0x47, 0x3a, 0xec, 0x45, 0xea };
                aes.IV = IV;
                Rfc2898DeriveBytes Key = new Rfc2898DeriveBytes(client_id + client_id,
                    Encoding.ASCII.GetBytes("Ivan Medvedev"));
                aes.Key = Key.GetBytes(32);
                using (FileStream fs = File.Create(Environment.MachineName + "_LogicDisk" + dir.Substring(0, 1) + "_decrypt_log.csv"))
                {
                    using (StreamWriter writer = new StreamWriter(fs, Encoding.Default))
                    {
                        int count_decr_files = 0;
                        int count_not_decr_files = 0;

                        string separator = ";";
                        StringBuilder headings_out = new StringBuilder();
                        string[] headings = {"DataTime", "Flag", "Encrypted Filename", "Original Filename" };
                        headings_out.AppendLine(string.Join(separator, headings));
                        writer.Write(headings_out);

                        foreach (var path in path_enc_file_arr)
                        {
                            try
                            {   
                                StringBuilder output = new StringBuilder();
                                var original_file_path = decryptFiles(path, aes);             
                                string[] newLine = { DateTime.Now.ToString(), "FILE DECRYPTED", path, original_file_path };
                                output.AppendLine(string.Join(separator, newLine));
                                writer.Write(output);
                                count_decr_files++;

                            }

                            catch
                            {
                                StringBuilder output = new StringBuilder();
                                string[] newLine = { DateTime.Now.ToString(), "FAILED TO DECRYPT FILE", path };
                                output.AppendLine(string.Join(separator, newLine));
                                writer.Write(output);
                                count_not_decr_files++;
                            }
                        }
                        writer.Write(";Total encrypted files: " + path_enc_file_arr.Length +  "\n");
                        writer.Write(";Decrypted files count: " + count_decr_files + "\n");
                        writer.Write(";Not decrypted files count: " + count_not_decr_files + "\n");
                        Console.WriteLine(dir);
                        Console.WriteLine("Total encrypted files: " + path_enc_file_arr.Length);
                        Console.WriteLine("Decrypted files count: " + count_decr_files);
                        Console.WriteLine("Not decrypted files count: " + count_not_decr_files);
                    }

                }

            }
        }

        static void DecryptFile(string file_path, string client_id)
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.BlockSize = 128;
                aes.KeySize = 256;
                byte[] IV = new byte[] { 0x5c, 0xd2, 0x23, 0x95, 0xee, 0xef, 0x2a, 0x45, 0x25, 0x47, 0xaa, 0x47, 0x3a, 0xec, 0x45, 0xea };
                aes.IV = IV;
                Rfc2898DeriveBytes Key = new Rfc2898DeriveBytes(client_id + client_id,
                    Encoding.ASCII.GetBytes("Ivan Medvedev"));
                aes.Key = Key.GetBytes(32);
                try
                {
                    decryptFiles(file_path, aes);
                    Console.WriteLine("|FILE DECRYPTED|");
                }
                catch
                {
                    Console.WriteLine("|FAILED TO DECRYPT FILE|");
                }

            }
        }
        static string GetClientID()
        {
            string[] array = new string[5];
            array[0] = wmi_select("Win32_BaseBoard", "Name,Manufacturer,Version");
            array[1] = wmi_select("Win32_Bios", "Name,Manufacturer,Version");
            array[2] = wmi_select("Win32_Processor", "Name,Manufacturer,ProcessorId");
            array[3] = wmi_select("Win32_DiskDrive", "Name,Manufacturer,Model");
            array[4] = wmi_select("Win32_VideoController", "Name,DeviceID,DriverVersion");

            string processorId = wmi_get_processorId();
            string baseboardProduct = wmi_get_product();
            string mac = wmi_get_mac();
            string md5_str = processorId + baseboardProduct + mac;
            string md5_hash = md5(md5_str).ToUpper();
            string client_id_str = String.Join(string.Empty, array) + md5_hash + processorId.Substring(9, 4);
            string client_id = sha1(client_id_str);
            return client_id;
        }
        static void Main(string[] args)
        {
            string client_id = "";
            string dir = "";

            if (args.Length == 0)
            {
                Console.WriteLine("\nNo argument has been specified");
                ShowHelp();
            }

            for (int i = 0; i < args.Length; i++)
            {

                if (args[i] == "-help")
                {
                    ShowHelp();

                    break;
                }
                
                if (args[i] == "-getid")
                {
                    Console.WriteLine(GetClientID());
                }

                if (args[i] == "-id")
                {
                    if (i + 1 >= args.Length)
                    {
                        Console.WriteLine("Missing argument!");
                        break;
                    }
                    else
                    {
                        client_id = args[i + 1];

                        if (args[i + 2] == "-d")
                        {
                            dir = args[i + 3];
                            DecryptDir(dir, client_id);
                        }
                        else
                        {
                            if (args[i + 2] == "-f")
                            {
                                string file_path = args[i + 3];
                                DecryptFile(file_path, client_id);

                            }
                            else
                            {
                                if (args[i + 2] == "-all")
                                {
                                    DriveInfo[] allDrives = DriveInfo.GetDrives();
                                    foreach (DriveInfo d in allDrives)
                                    {
                                        DecryptDir(d.Name, client_id);
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
                else
                {
                    if (args[i] == "-d")
                    {
                        dir = args[i + 1];
                        DecryptDir(dir, GetClientID());
                    }
                    else
                    {
                        if (args[i] == "-f")
                        {
                            string file_path = args[i + 1];
                            DecryptFile(file_path, GetClientID());
                        }
                        else
                        {
                            if (args[i] == "-all")
                            {
                                DriveInfo[] allDrives = DriveInfo.GetDrives();
                                foreach (DriveInfo d in allDrives)
                                {
                                    DecryptDir(d.Name, GetClientID());
                                }
                            }
                        }
                    }
                }
            }

        }
    }
}
