using System;
using System.Text;

public class ShellcodeEncoder
{
    private static Random random = new Random();

    public static void Main(string[] args)
    {
        // Raw shellcode byte array.
        byte[] shellcode = new byte[] {};

        // Generate a dynamic XOR key (8 bytes in this example)
        byte[] xorKey = new byte[8];
        random.NextBytes(xorKey);

        // XOR Encrypt the shellcode
        byte[] xoredShellcode = XOREncrypt(shellcode, xorKey);

        // Combine XOR key and xored shellcode
        byte[] combinedData = new byte[xorKey.Length + xoredShellcode.Length];
        Array.Copy(xorKey, 0, combinedData, 0, xorKey.Length);
        Array.Copy(xoredShellcode, 0, combinedData, xorKey.Length, xoredShellcode.Length);

        // Custom Base64 alphabet
        const string customAlphabet = "WYXADCBEFGHIJPLMNOKQRSTUVZzyxabcdefghijklmnopqrstuvw0123456789+/";

        // Base64 encode the combined data using custom alphabet
        string encodedShellcode = CustomBase64Encode(combinedData, customAlphabet);

        Console.WriteLine(encodedShellcode);
    }

    private static byte[] XOREncrypt(byte[] data, byte[] key)
    {
        byte[] encrypted = new byte[data.Length];

        for (int i = 0; i < data.Length; i++)
        {
            encrypted[i] = (byte)(data[i] ^ key[i % key.Length]);
        }

        return encrypted;
    }

private static string CustomBase64Encode(byte[] input, string alphabet)
{
    string standardEncoded = Convert.ToBase64String(input);
    StringBuilder customEncoded = new StringBuilder(standardEncoded.Length);

    foreach (char c in standardEncoded)
    {
        if (c == '+') customEncoded.Append(alphabet[62]);
        else if (c == '/') customEncoded.Append(alphabet[63]);
        else if (c == '=') customEncoded.Append('=');
        else if (char.IsDigit(c)) customEncoded.Append(alphabet[c - '0' + 52]);
        else if (char.IsUpper(c)) customEncoded.Append(alphabet[c - 'A']);
        else if (char.IsLower(c)) customEncoded.Append(alphabet[c - 'a' + 26]);
    }

    return customEncoded.ToString();
}

}
