# SniperPOV

By default, in a POV demo, TF2 makes the local sniper invisible when you scope in. This is a small loader that fixes that.
Meant to be used alongside HLAE.

# Instructions 

Download the latest release. Extract and obtain the "SniperPOV.dll" and "SniperPOVx64.dll" files.

Method 1 (HLAE only): Open HLAE's custom loader (Tools > Developer > Custom Loader) and add SniperPOV.dll (32bit) <ins>OR</ins> SniperPOVx64.dll (64bit) to the list of dlls. Make sure you've prepared the custom loader properly for launch in either 32-bit or 64-bit (eg. 64-bit instructions: https://github.com/advancedfx/advancedfx/wiki/AfxHookSource#launching-team-fortress-2-x64). Then press OK to launch.

Method 2 (HLAE & Lawena, 32-bit only): You need a special version of Lawena, which can be obtained here: https://github.com/wgez/lawena-recording-tool/releases.

Method 3 (RISKY - HLAE & Injector): If you have an injector file and know what you're doing, you can inject your desired .dll file after launching HLAE. Heed the warning below.

## DO NOT RUN WITHOUT INSECURE MODE

If you want to inject this without HLAE, DO NOT FORGET TO USE INSECURE MODE. You WILL be VAC banned if you forget and accidentally join a VAC protected server.

## Updates

The stability of this tool is vulnerable to TF2 updates, so if it breaks please make an issue.

## How to Build (for developers)
1. Install GIT bash (to obtain source code) - https://git-scm.com/downloads
2. Install Visual Studio (not Visual Studio Code) with "Desktop development with C++" - https://visualstudio.microsoft.com/
3. From within Visual Studio, obtain the source code from this repository into a folder you like (Clone a Repository option, upon startup).
4. Once you've opened the SniperPOV project (with SniperPOV.sln), open the Configuration Manager (Build -> Configuration Manager...).
5. If you want to build for 32-bit: Change "Active solution configuration" to "Release" and "Active solution platform" to "x86".
6. If you want to build for 64-bit: Change "Active solution configuration" to "Release" and "Active solution platform" to "x64".
7. Build -> Build Solution. This will generate a SniperPOV.dll file at "[your repos location "SniperPOV"]/SniperPOV/Release" for 32-bit and "[your repos location "SniperPOV"]/SniperPOV/x64/Release" for 64-bit.

If necessary (shouldn't be needed), detours.lib instructions:
1. In a separate instance (can restart VS), obtain the source code for Microsoft Detours - https://github.com/microsoft/Detours.
2. For 32-bit: Build Detours for x86 (Build -> Build Solution). It will generate a "detours.lib" file at "[your repos location "Detours"]/lib.X86/".
3. For 64-bit: Build Detours for x64 (Build -> Build Solution). It will generate a "detours.lib" file at "[your repos location "Detours"]/lib.X64/".
4. In your SniperPOV repository, insert your "detours.lib" file into "[your repos location "SniperPOV"]/SniperPOV/SniperPOV/lib/x86" for 32-bit and "[your repos location "SniperPOV"]/SniperPOV/SniperPOV/lib/x64" for 64-bit.
