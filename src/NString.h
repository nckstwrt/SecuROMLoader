#ifndef __NSTRING_H__
#define __NSTRING_H__

#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4996)
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <string>

class NString
{	
public:
	NString()
	{
	}

	NString(const char *szString)
	{
		if ( szString )
			theString = szString;
	}

	NString(const wchar_t *pString)
	{
		if ( pString )
		{
			size_t outsize = 0;
			size_t len = wcslen(pString);
			char *szString = new char[len+1];
			size_t a = wcstombs( szString, pString, len+1);
			theString = szString;
			delete [] szString;
		}
	}

	static NString IntToCStringPort(int n)
	{
		return Format("%d", n);
	}

	static NString Format(const char* fmt, ...)
	{
		NString csRet;
		char *printString = NULL;
		va_list argp;
		va_start(argp, fmt);
		vasprintf(&printString, fmt, &argp);
		va_end(argp);
		csRet = printString;
		delete [] printString;
		return csRet;
	}

	static NString GUIDToCStringPort(GUID guid)
	{
		return Format("{%08x-%04x-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}",
					 guid.Data1, guid.Data2, guid.Data3,
					 guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
					 guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	}

	NString Replace(int chOld, int chNew)
	{
		NString ret = theString.c_str();
		for ( int i = 0; i != ret.theString.size(); i++ )
			if (ret.theString[i] == chOld )
				ret.theString[i] = chNew;
		return ret;
	}

	NString Replace(const char* szOld, const char* szNew)
	{
		NString ret = theString.c_str();
		for ( size_t j = 0; (j = ret.theString.find(szOld)) != std::string::npos; )
			ret.theString.replace(j, strlen(szOld), szNew);
		return ret;
	}

	NString SubString(int Start, int Count = -1)
	{
		NString csRet;
		int EndPos = Start + Count;
		if ( EndPos > (int)theString.size() || Count == -1 )
			EndPos = (int)theString.size();
		for ( int i = Start; i != EndPos; i++ )
			csRet += theString[i];
		return csRet;
	}

	NString Left(int nCount)
	{
		NString csRet;
		if ( nCount > 0 )
		{
			if ( nCount > (int)theString.size() )
				nCount = (int)theString.size();
			for  ( int i = 0; i != nCount; i++ )
				csRet += theString[i];
		}
		return csRet;
	}

	NString Right(int nCount)
	{
		NString csRet;

		if ( nCount > 0 )
		{
			if ( nCount > (int)theString.size() )
				nCount = (int)theString.size();
				
			for  ( int i = nCount; i != 0; i-- )
				csRet += theString[theString.size()-i];
		}

		return csRet;
	}

	bool Contains(const char *szFind)
	{
		return Find(szFind) != -1 ? true : false;
	}

	int Find(const char *szFind)
	{
		int nRet = -1;
		char *pPtr = (char*)strstr(theString.c_str(), szFind);
		if ( pPtr )
		{
			nRet = (int)(pPtr - theString.c_str());
		}
		return nRet;
	}

	int Find(int c)
	{
		int nRet = -1;
		for ( int i = 0; i != theString.size(); i++ )
		{
			if ( theString[i] == c )
			{
				nRet = i;
				break;
			}
		}
		return nRet;
	}

	int ReverseFind(int c)
	{
		int nRet = -1;
		for ( int i = (int)(theString.size()-1); i != -1; i-- )
		{
			if ( theString[i] == c )
			{
				nRet = i;
				break;
			}
		}
		return nRet;
	}

	void InsertAt(int nIndex, NString csStr)
	{
		NString csCurrentStr = theString.c_str();

		NString csLeft = csCurrentStr.Left(nIndex);
		NString csRight = csCurrentStr.Right(csCurrentStr.GetLength()-nIndex);

		theString = csLeft + csStr + csRight;
	}

	void SetAt(int nIndex, int c)
	{
		theString[nIndex] = c;
	}

	int GetAt(int nIndex)
	{
		return theString[nIndex];
	}

	NString ToLower()
	{
		NString csRet;
		for (int i = 0; i != theString.size(); i++)
			csRet += tolower(theString[i]);
		return csRet;
	}

	NString ToUpper()
	{
		NString csRet;
		for ( int i = 0; i != theString.size(); i++ )
			csRet += toupper(theString[i]);
		return csRet;
	}

	int Compare(const char *szText)
	{
		return strcmp(theString.c_str(), szText);
	}

	int CompareNoCase(const char *szText)
	{
		return _stricmp(theString.c_str(), szText);
	}

	NString Trim()
	{
		NString csTemp;

		int i, nStart = 0, nEnd = 0;
		for ( i = 0; i != theString.size(); i++ )
		{
			if ( theString[i] != ' ' )
			{
				nStart = i;
				break;
			}
		}
		for ( i = (int)theString.size(); i != 0; i-- )
		{
			if ( theString[i-1] != ' ' )
			{
				nEnd = i;
				break;
			}
		}
		for ( i = nStart; i != nEnd; i++ )
		{
			csTemp += (int)theString[i];
		}

		return csTemp;
	}

	bool EndsWith(const char *szText)
	{
		if ( szText == NULL || theString.size() < strlen(szText) )
			return false;
		int nStart = (int)(theString.size() - strlen(szText));
		for ( int i = 0; i != strlen(szText); i++ )
		{
			if ( theString[nStart + i] != szText[i] )
				return false;
		}
		return true;
	}

	bool StartsWith(const char *szText)
	{
		if ( szText == NULL || theString.size() < strlen(szText) )
			return false;
		for ( int i = 0; i != strlen(szText); i++ )
		{
			if ( theString[i] != szText[i] )
				return false;
		}
		return true;
	}

	int operator[](int pos)
	{
		return theString[pos];
	}

	bool operator<(const NString right) const
	{
		return (strcmp(theString.c_str(), right) < 0);
	}

	bool operator==(const NString right) const
	{
		return (strcmp(theString.c_str(), right) == 0);
	}

	bool operator!=(const NString right) const
	{
		return (strcmp(theString.c_str(), right) != 0);
	}

	bool operator==(const char *szRight) const
	{
		return (strcmp(theString.c_str(), szRight) == 0);
	}

	bool operator!=(const char *szRight) const
	{
		return (strcmp(theString.c_str(), szRight) != 0);
	}

	operator const char*() const
	{	
		return theString.c_str();
	}

	operator const wchar_t*() const
	{	
		size_t outsize = 0;
		size_t len = theString.size()+1;
		wchar_t *szString = new wchar_t[len];
		mbstowcs(szString, theString.c_str(), len);
		theWideString = szString;
		delete [] szString;
		return theWideString.c_str();
	}

	NString operator+(const NString& str) const
	{
		std::string newStr = (const char *)str;
		std::string newStr2 = theString + newStr;
		return NString(newStr2.c_str());
	}

	const NString& operator+=(NString str)
	{
		std::string newStr = (const char *)str;
		std::string newStr2 = theString + newStr;
		theString = newStr2.c_str();
		return *this;
	}

	const NString& operator+=(const char* str)
	{
		std::string newStr = str;
		std::string newStr2 = theString + newStr;
		theString = newStr2.c_str();
		return *this;
	}

	const NString& operator+=(int n)
	{
		NString temp = Format("%c", (int)n);
		std::string newStr = (const char *)temp;
		std::string newStr2 = theString + newStr;
		theString = newStr2.c_str();
		return *this;
	}

	const NString& operator+=(unsigned const char* str)
	{
		std::string newStr = (const char *)str;
		std::string newStr2 = theString + newStr;
		theString = newStr2.c_str();
		return *this;
	}

	const NString& operator=(unsigned const char* str)
	{
		std::string newStr = (const char *)str;
		theString = newStr.c_str();
		return *this;
	}

	const NString& operator=(const wchar_t* str)
	{
		size_t outsize = 0;
		size_t len = wcslen(str);
		char* szString = new char[len + 1];
		size_t a = wcstombs(szString, str, len + 1);
		theString = szString;
		delete[] szString;
		return *this;
	}

	void Empty()
	{
		theString = "";
	}

	bool IsEmpty() const
	{
		return theString == "";
	}

	int GetLength()
	{
		return (int)theString.size();
	}

private:
	std::string theString;
	mutable std::wstring theWideString;

	// Would be nice:
	// int _vscprintf(const char *format, va_list argptr);
	// For MinGW/Visual Studio
	static int vasprintf(char** result, const char* format, va_list* args)
	{
		const char* p = format;
		int total_width = (int)strlen(format) + 1;
		va_list ap;

		memcpy(&ap, args, sizeof(va_list));

		while (*p != '\0')
		{
			if (*p++ == '%')
			{
				while (strchr("-+ #0", *p))
					++p;
				if (*p == '*')
				{
					++p;
					total_width += abs(va_arg(ap, int));
				}
				else
					total_width += strtoul(p, (char**)&p, 10);
				if (*p == '.')
				{
					++p;
					if (*p == '*')
					{
						++p;
						total_width += abs(va_arg(ap, int));
					}
					else
						total_width += strtoul(p, (char**)&p, 10);
				}
				while (strchr("hlL", *p))
					++p;
				// Should be big enough for any format specifier except %s and floats.  
				total_width += 30;
				switch (*p)
				{
				case 'd':
				case 'i':
				case 'o':
				case 'u':
				case 'x':
				case 'X':
				case 'c':
					(void)va_arg(ap, int);
					break;
				case 'f':
				case 'e':
				case 'E':
				case 'g':
				case 'G':
					(void)va_arg(ap, double);
					// Since an ieee double can have an exponent of 307, we'll
				   //make the buffer wide enough to cover the gross case. 
					total_width += 307;
					break;
				case 's':
					total_width += (int)strlen(va_arg(ap, char*));
					break;
				case 'p':
				case 'n':
					(void)va_arg(ap, char*);
					break;
				}
				p++;
			}
		}
		*result = (char*)malloc(total_width);
		if (*result != NULL)
			return vsprintf(*result, format, *args);
		else
			return 0;
	}
};

inline NString operator+(const char*& s1, const NString& s2)
{
	std::string str1 = s1;
	std::string str2 = (const char *)s2;
	std::string str3 = str1 + str2;
	NString sRet(str3.c_str());
	return sRet;
}

inline NString operator+(const char* s1, const NString& s2)
{
	std::string str1 = s1;
	std::string str2 = (const char *)s2;
	std::string str3 = str1 + str2;
	NString sRet(str3.c_str());
	return sRet;
}

inline NString operator+(const NString& s1, const char*& s2)
{
	std::string str1 = (const char *)s1;
	std::string str2 = s2;
	std::string str3 = str1 + str2;
	NString sRet(str3.c_str());
	return sRet;
}

#endif