#include <windows.h>
#include "Utils.h"
#include "Config.h"
#include "NString.h"
#include "Compatibility.h"
#include "minhook/MinHook.h"
#include <GL/gl.h>
#include <vector>

extern Config config;

void GTAVCMouseFix()
{
	// GTA VC - Mouse fucking fix! (from https://github.com/CookiePLMonster/SilentPatch/blob/0cefc58fefd8fb4154130edeba69b169d930f78e/SilentPatchVC/SilentPatchVC.cpp#L2534)
	if (IsReadablePointer((void*)0x601740) && *((DWORD*)(0x601740)) == 0x3EEC0D8B)
	{
		logc(FOREGROUND_CYAN, "Patching Mouse Fix at 0x601740 - Currently: %08X\n", *((DWORD*)(0x601740)));
		WriteProtectedDWORD(0x601740, 0xC3C030);
	}
	if (IsReadablePointer((void*)0x601770) && *((DWORD*)(0x601770)) == 0x3EEC0D8B)
	{
		logc(FOREGROUND_CYAN, "Patching Mouse Fix at 0x601770 - Currently: %08X\n", *((DWORD*)(0x601770)));
		WriteProtectedDWORD(0x601770, 0xC3C030);
	}
}

void ApplyCompatibilityPatches()
{
	GTAVCMouseFix();
	RestrictProcessors(config.GetInt("CPUCount", -1));
	SetProcessDPIAware();
}

void CheckForCrysis3DNowIssue()
{
	HMODULE crysystemBase = NULL;
	DWORD crysystemSize = 0;
	if (GetLoadedDllBaseAndSize("crysystem.dll", &crysystemBase, &crysystemSize))
	{
		logc(FOREGROUND_CYAN, "crysystem.dll Base: %08X Size: %X\n", (DWORD)crysystemBase, crysystemSize);
		DWORD ThreeDNowCheck = FindHexString((DWORD)crysystemBase, (DWORD)crysystemBase + crysystemSize, "C1E902F6C10174", "crysystem 3DNow Checks");
		if (ThreeDNowCheck != -1L)
		{
			WriteProtectedDWORD(ThreeDNowCheck, 0x90909090);
			WriteProtectedDWORD(ThreeDNowCheck + 4, 0x90909090);
			WriteProtectedDWORD(ThreeDNowCheck + 8, 0xC3909090);
		}
	}
}

const GLubyte* (WINAPI* glGetString_ori)(GLenum name);
GLubyte extensionList[1024];

std::vector<std::string>requiredExtensions =
{
	"GL_ARB_fragment_program",
	"GL_ARB_multitexture",
	"GL_ARB_texture_compression",
	"GL_ARB_texture_cube_map",
	"GL_ARB_texture_env_combine",
	"GL_ARB_texture_env_dot3",
	"GL_ARB_vertex_buffer_object",
	"GL_ARB_vertex_program",
	"GL_EXT_bgra",
	"GL_EXT_secondary_color",
	"GL_EXT_stencil_two_side",
	"GL_EXT_stencil_wrap",
	"GL_EXT_texture_compression_s3tc",
	"GL_EXT_texture_filter_anisotropic",
	"GL_EXT_texture_lod_bias",
	"GL_NV_copy_depth_to_color",
	"GL_NV_fence",
	"GL_NV_fragment_program",
	"GL_NV_fragment_program_option",
	"GL_NV_fragment_program2",
	"GL_NV_occlusion_query",
	"GL_NV_register_combiners",
	"GL_NV_register_combiners2",
	"GL_NV_texture_shader",
	"GL_NV_vertex_array_range",
	"GL_NV_vertex_program"
};

const GLubyte* WINAPI glGetString_hook(GLenum name)
{
	if (name == GL_EXTENSIONS)
	{
		// This will contain our extensions
		std::string vendorstr = reinterpret_cast<const char*>(glGetString_ori(GL_VENDOR));
		std::string extList;

		// Get extensions and build our own list with the required ones only
		std::string extensions = reinterpret_cast<const char*>(glGetString_ori(GL_EXTENSIONS));
		for (size_t i = 0; i < requiredExtensions.size(); i++)
		{
			size_t pos = 0;
			pos = extensions.find(requiredExtensions[i]);
			if (pos != std::string::npos)
				extList += requiredExtensions[i] + " ";
		}
		memcpy(extensionList, extList.c_str(), extList.size() + 1);
		return extensionList;
	}
	return glGetString_ori(name);
}

void RiddickGLFix()
{
	HMODULE rndrglBase = NULL;
	DWORD rndrglSize = 0;
	if (GetLoadedDllBaseAndSize("rndrgl.dll", &rndrglBase, &rndrglSize))
	{
		logc(FOREGROUND_CYAN, "rndrgl.dll Base: %08X Size: %X\n", (DWORD)rndrglBase, rndrglSize);
		
		char rndrglDir[MAX_PATH];
		if (GetDirectoryOfDLL("rndrgl.dll", rndrglDir, MAX_PATH))
		{
			logc(FOREGROUND_CYAN, "rndrgl.dll Directory: %s\n", rndrglDir);
			NString dir = rndrglDir;
			dir += "\\TCoRFix.asi";
			logc(FOREGROUND_CYAN, "Checking for TCoRFix.asi in rndrgl.dll directory: %s\n", (LPCSTR)dir);
			if (GetFileAttributes(dir) != -1L)
			{
				logc(FOREGROUND_CYAN, "TCoRFix.asi found, skipping built in OpenGL extension hook. Loading asi\n");
				LoadLibraryA("TCoRFix.asi");
			}
			else
			{
				logc(FOREGROUND_CYAN, "TCoRFix.asi not found, applying built in OpenGL extension hook\n");
				LoadLibraryA("opengl32.dll");
				MH_CreateHookApi(L"opengl32.dll", "glGetString", glGetString_hook, (void**)&glGetString_ori);
				MH_EnableHook(MH_ALL_HOOKS);
			}
		}
		else
			logc(FOREGROUND_RED, "Failed to get rndrgl.dll directory!\n");

		GetKey(true);
	}
}

void ApplyDLLCompatibilityPatches(LPCSTR lpLibFileName)
{
	if (lpLibFileName)
	{
		NString libName = lpLibFileName;
		libName = libName.ToLower();
		if (libName.Contains("crysystem"))
			CheckForCrysis3DNowIssue();
		if (libName.Contains("rndrgl.dll"))
			RiddickGLFix();
	}
}

