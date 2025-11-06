#pragma once
#include <Windows.h>
#include "Utils.h"
#include "tiny-json.h"
#include <tuple> 
#include <string>
#include <vector>

class Config
{
public:
    Config();
    ~Config();

    bool LoadConfig(const char* szConfigFile);
    const char* GetValue(const char* szPropertyName);
    bool GetBool(const char* szPropertyName, bool defaultReturn = false);
    int GetInt(const char* szPropertyName, int defaultReturn = 0);
    std::string GetFileMapping(const char* szSourceFile);

    std::vector<std::tuple<const char*, const char*>> fileMappings;

private:
    void freeJSON();
    std::vector<std::tuple<const char*, const char*>> GetFileMappings();

    char* buffer;
    json_t* jsonMemory;
    const json_t* jsonRoot;
};

int TestConfig();
