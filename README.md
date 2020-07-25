# FormsAuthentication.Decryptor

[![NuGet version (FormsAuthentication.Decryptor)](https://img.shields.io/nuget/v/FormsAuthentication.Decryptor)](https://www.nuget.org/packages/FormsAuthentication.Decryptor/)

A library to decrypt Forms Authentication cookies on the .NET Core runtime. Typically these cookies are created
on older/legacy ASP.NET applications running .NET Framework, but may need to be decrypted/validated in a cloud
or serverless context running .NET Core, e.g. AWS Lambda.

## Notes

- At the time of writing, .NET Core 2.1 does not include the APIs for decrypting FormsAuthentication cookies.
  However, Microsoft has open-sourced .NET Framework, allowing us to easily port the code to .NET Core.

  - https://github.com/microsoft/referencesource/tree/master/System.Web
  - https://referencesource.microsoft.com

- This version supports AES (for decryption) and HMAC256/384/512 (hashing).

- It can decode Forms Auth cookies created for MachineKeyCompatibilityMode.Framework45 and above.

  - For cookies created on Framework20SP1 or Framework20SP2, see https://www.nuget.org/packages/AspNetCore.LegacyAuthCookieCompat/

- The code is unchanged from the original version except:

  - Unused methods removed
  - Removed code for encryption - e.g. NetFXCryptService.Protect(...) method - leaving only decryption code
  - Some comments removed

- The code has been released by Microsoft under the MIT license.
