#define _CRT_SECURE_NO_WARNINGS
#include "Config.h"
#include "Utils.h"
#include "NString.h"

#define MAX_FIELDS 100

Config::Config()
{
	buffer = nullptr;
	jsonMemory = nullptr;
	jsonRoot = nullptr;
}

Config::~Config()
{
    freeJSON();
}

void Config::freeJSON()
{
	if (buffer)
	{
		delete[] buffer;
		buffer = nullptr;
	}
	if (jsonMemory)
	{
		delete[] jsonMemory;
		jsonMemory = nullptr;
	}
	jsonRoot = nullptr;
}


bool Config::LoadConfig(const char* szConfigFile)
{
    bool bResult = false;

    FILE* fp = fopen(szConfigFile, "rb");
    if (fp)
    {
        freeJSON();

        fseek(fp, 0, SEEK_END);
        long fileSize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (fileSize > 0)
        {
            buffer = new char[fileSize + 1];
            if (buffer)
            {
                size_t bytesRead = fread(buffer, sizeof(char), fileSize, fp);
                if (bytesRead == (size_t)fileSize)
                {
                    buffer[fileSize] = '\0'; // Ensure null-termination

                    jsonMemory = new json_t[MAX_FIELDS];

                    jsonRoot = json_create(buffer, jsonMemory, MAX_FIELDS);
                    if (jsonRoot)
                    {
						fileMappings = GetFileMappings();
                        bResult = true; // Successfully parsed JSON
                    }
                }
                else
                {
                    delete[] buffer;
                    buffer = nullptr;
                }
            }
        }
        fclose(fp);
    }

    return bResult;
}

const char* Config::GetValue(const char* szPropertyName, const char *szDefaultValue)
{
    if (jsonRoot)
        return json_getPropertyValue(jsonRoot, szPropertyName);
    return szDefaultValue;
}

bool Config::GetBool(const char* szPropertyName, bool defaultReturn)
{
	bool bResult = defaultReturn;
    if (jsonRoot)
    {
        const char *value = json_getPropertyValue(jsonRoot, szPropertyName);
        if (value)
            bResult = (_stricmp(value, "true") == 0);
    }
    return bResult;
}

int Config::GetInt(const char* szPropertyName, int defaultReturn)
{
    int nResult = defaultReturn;
    if (jsonRoot)
    {
        const char* value = json_getPropertyValue(jsonRoot, szPropertyName);
        if (value)
        {
			nResult = atoi(value);
        }
    }
    return nResult;
}

std::string Config::GetFileMapping(const char* szSourceFile)
{
    if (szSourceFile)
    {
        for (const auto& mapping : fileMappings)
        {
		    const char* source = std::get<0>(mapping);
            if (source[0] != 0 && source[strlen(source)-1] == '*')
            {
				// Wildcard source! more lengthy so do separately
				NString csSource(source);
                NString csTarget(std::get<1>(mapping));
				NString csFile(szSourceFile);

                csSource = csSource.Replace("*", "");
				csSource = csSource.ToLower();
				csFile = csFile.ToLower();
				if (csFile.StartsWith(csSource))
                {
                    csTarget = csTarget.Replace("*", "");
                    csFile = csFile.Replace(csSource, csTarget);
                    logc(FOREGROUND_BLUE, "File Mapping match %s: %s -> %s\n", std::get<0>(mapping), szSourceFile, (LPCSTR)csFile);
					return (LPCSTR)csFile;
                }
            }
            else
            {
                if (_stricmp(source, szSourceFile) == 0)
                {
			        logc(FOREGROUND_BLUE, "File Mapping match %s: %s -> %s\n", std::get<0>(mapping), szSourceFile, std::get<1>(mapping));
                    return std::get<1>(mapping);
                }
            }
        }
    }
    return szSourceFile;
}

std::vector<std::tuple<const char*, const char*>> Config::GetFileMappings()
{
    std::vector<std::tuple<const char*, const char*>> values;
    const json_t* fileMappings = json_getProperty(jsonRoot, "fileMappings");
    if (fileMappings && json_getType(fileMappings) == JSON_ARRAY)
    {
        for (const json_t* mapping = json_getChild(fileMappings); mapping != nullptr; mapping = json_getSibling(mapping))
        {
            if (json_getType(mapping) == JSON_OBJ)
            {
                const char* source = json_getPropertyValue(mapping, "source");
                const char* target = json_getPropertyValue(mapping, "target");
                if (source && target) {
                    values.push_back(std::make_tuple(source, target));
                }
            }
        }
    }

    return values;
}

int TestConfig()
{
    Config config;
	char szDir[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, szDir);
	printf("Current Directory: %s\n", szDir);
    bool loaded = config.LoadConfig("version.json");
    if (loaded) 
    {
        const char *exeFile = config.GetValue("exeFile");
        if (exeFile)
            printf("Executable File: %s\n", exeFile);
        else
			printf("Executable File not found in configuration.\n");    

        const char *logging = config.GetValue("logging");
        if (logging)
            printf("logging: %s\n", logging);

		auto fileMappings = config.fileMappings;
        if (!fileMappings.empty())
        {
            printf("File Mappings:\n");
            for (const auto& mapping : fileMappings)
            {
                printf("Source: %s, Target: %s\n", std::get<0>(mapping), std::get<1>(mapping));
            }
        }
        else
			printf("No file mappings found in configuration.\n");
	}
    else
        printf("Failed to load configuration file.\n");

    return 0;
}