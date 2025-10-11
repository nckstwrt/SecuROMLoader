# SecuROMLoader
Allows playing SecuROM games (versions 4,5,6 and 7) on Modern Windows without the need of the CD/DVD

# Download
[Releases](https://github.com/nckstwrt/SecuROMLoader/releases)

## Usage
SecuROMLoader is primarily just "version.dll". For any newer game you can just place version.dll in the same directory as the game's main executable and the game can then be run normally. It will then automatically use version.dll without any further changes required to bypass SecuROM.

## Configuration
SecuROMLoader can be configured to bypass additional CD/DVD checks and log lots of debug information.  
Find out more here: [Example Config Files](https://github.com/nckstwrt/SecuROMLoader/tree/main/Example%20Config%20Files)

## Credits
* ELF_7719116 - The mastermind behind unveiling SecuROM and describing the technique used to NoCD SecuROM 7 (as described in TIBERIUMNUY_REVERSING__FULL_PUBLIC_VERSION_1.3.pdf)
* SecuROM v3, v4, v5 approach by me

## Tested and Working Games + Versions
* Crysis - v7.34.0014
* Command and Conquer 3 (v1.9) - v7.33.0017
* Prototype - v7.39.0006
* Pro Evolution Soccer 3 - v4.85.04
* Magic The Gathering - Battlegrounds - v4.85.07
* Counterstrike - Condition Zero - v5.00.03 (May need to use VersionInjector (or just rename the exe))
* Grand Theft Auto - Vice City 1.0 - v4.84.69
* Grand Theft Auto - Vice City 1.1 - v4.84.75
* Manhunt - v5.03.03
* Max Payne 2 v1.01 - v4.85.07 - Needs SafeSEH turned off in the exe manually (log file will tell you how)
* Football Manager 2008 - v7.34.0013 (has SafeSEH but works anyway)
* Driv3r - v5.03.13
* X-2 The Threat - v5.00.03
* Sid Meier's Pirates! - v5.03.06 - This is the most interesting one! Far more obfuscation than the versions below or above it! Needed a separate approach
* Football Manager 2008 - v7.34.0013
* Diablo 2 - v3.17.00
* Diablo 2 - Lord of Destruction - v4.47.00
* Gunman Chronicles - v4.16.00
* Homeworld Cataclysm - v4.08.00 - (May need to use VersionInjector)
* Kohan Ahrimans Gift v1.37 - v4.84.63
* Jurassic Park Operation Genesis - v4.84.64
* Chronicles of Riddick Escape from Butcher Bay - v5.03.09
* Spellforce - The Order of Dawn v1.11 - v5.00.03
* Spellforce - The Breath Of Winter - v5.03.04

## Background
After writing  [SafeDiscLoader2](https://github.com/nckstwrt/SafeDiscLoader2) I was interested in creating the same for SecuROM as these were the two big CD/DVD protections before Internet Activation took over (as it did even for SecuROM 8). ELF described how you can bypass the protection in SecuROM 7 so I wanted to implement a generic way of doing the same for every version I could find.

