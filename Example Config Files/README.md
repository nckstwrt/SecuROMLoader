# SecuROMLoader Config Files
Example JSON based config files to assist with extra cd checks on some games.  
Just add the text like the below into a text file called version.json and place next to version.dll for it to take effect
Config files can also be modified to assist in debugging issues, logging, ejecting the safedisc debugger, etc

## Example 1 (Kohan: Ahriman's Gift):
Makes L: appear to the game as being a CDROM drive and its volume name as KOHAN_AG which will bypass the extra cd check
```json
{
	"exeFile": "_AG.exe",
	"CDROMDriveLetter": "L",
	"CDROMVolumeName": "KOHAN_AG"
	"logging": true,
	"logFile": "version.log.txt"
}
```

## Can enable logging with:
```json
{
  "logging": true,
  "logFile": "version.log.txt"
}
```

