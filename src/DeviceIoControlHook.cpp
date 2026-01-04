#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <ntddscsi.h>
#include <map>
#include "IOCTLCodes.h"
#include "Config.h"
#include "NString.h"
#include "Utils.h"
#include "Typedefs.h"
#include "DeviceIoControlHook.h"
#include "SecuROM345Patching.h"

bool Securom7Confirmed = false;

extern Config config;

extern NtDeviceIoControlFile_typedef NtDeviceIoControlFile_Orig;
void PrintCdbCommand(const BYTE* cdb, UCHAR cdbLen);

BYTE *TOC = hexstring("0012010100140100000000000014AA000028FDD0");
int TOCCount = 0;
bool flip7C0 = true;

NTSTATUS NTAPI NtDeviceIoControlFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
	bool CaptureCDIO = config.GetBool("CaptureCDIO", false);
	
	if (DeviceIoControlMap.find(IoControlCode) != DeviceIoControlMap.end())
		logc(FOREGROUND_GREEN, "IOCTL %X (%s) (Handle: %X) InputBufferLength: %d OutputBufferLength: %d\n", IoControlCode, DeviceIoControlMap.find(IoControlCode)->second.c_str(), FileHandle, InputBufferLength, OutputBufferLength);
	
	if (IoControlCode == IOCTL_SCSI_PASS_THROUGH)
	{
		SCSI_PASS_THROUGH* spt = (SCSI_PASS_THROUGH*)InputBuffer;

		logc(FOREGROUND_CYAN, "IOCTL_SCSI_PASS_THROUGH - NOT DIRECT\n");

		PrintCdbCommand(spt->Cdb, spt->CdbLength);

		if (spt->Cdb[0] == 0x12) // INQUIRY = 0x12
		{
			IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
			return STATUS_UNSUCCESSFUL;
		}
				
		if (spt->Cdb[0] == 0x2b)
		{
			IoStatusBlock->Status = STATUS_SUCCESS;
			return STATUS_SUCCESS;
		}
		
		if (spt->Cdb[0] == 0x42 || spt->Cdb[0] == 0x2b) // READ SUB-CHANNEL + SEEK
		{
			DWORD xferLen = spt->DataTransferLength;
			IoStatusBlock->Status =STATUS_SUCCESS;
			IoStatusBlock->Information = xferLen;
			return STATUS_SUCCESS;
		}
	}

	if (IoControlCode == IOCTL_SCSI_PASS_THROUGH_DIRECT)// || IoControlCode == IOCTL_SCSI_PASS_THROUGH)  // IOCTL_SCSI_PASS_THROUGH = 0x4D004
	{
		NTSTATUS ret;
		if (InputBuffer && InputBufferLength >= sizeof(SCSI_PASS_THROUGH_DIRECT)) 
		{
			SCSI_PASS_THROUGH_DIRECT* sptd = (SCSI_PASS_THROUGH_DIRECT*)InputBuffer;

			logc(FOREGROUND_BROWN, "DataTransferLength: %u\n", sptd->DataTransferLength);

			PrintCdbCommand(sptd->Cdb, sptd->CdbLength);

			if (sptd->Cdb[0] == 0x12) // INQUIRY = 0x12
			{
				IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
				return STATUS_UNSUCCESSFUL;
			}

			if (sptd->Cdb[0] == 0x5A) // Opcode 0x5A: MODE SENSE(10)
			{
				logc(FOREGROUND_RED, "Faking MODE SENSE(10) response\n");	
				IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
				return STATUS_UNSUCCESSFUL;
			}

			if (sptd->Cdb[0] == 0x46) // Opcode 0x46: GET CONFIGURATION
			{
				logc(FOREGROUND_RED, "Faking GET CONFIGURATION response\n");
				IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
				return STATUS_UNSUCCESSFUL;
			}

			if ( sptd->Cdb[0] == 0x43) // READ TOC/PMA/ATIP = 0x43
			{
				if (CaptureCDIO)
				{
					ret = NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
					
					WriteToFile(NString::Format("sptd_TOC_%d.bin", TOCCount++), (BYTE*)sptd->DataBuffer, sptd->DataTransferLength);

					IoStatusBlock->Status = STATUS_SUCCESS;
					return STATUS_SUCCESS;
				}
				else
				{
					logc(FOREGROUND_RED, "Faking %s response\n", sptd->Cdb[0] == 0x12 ? "INQUIRY" : "READ TOC/PMA/ATIP");
					memcpy(sptd->DataBuffer, TOC, sptd->DataTransferLength);
					IoStatusBlock->Status = STATUS_SUCCESS;
					return STATUS_SUCCESS;
				}
			}

			if (sptd && sptd->CdbLength >= 10 && sptd->Cdb[0] == 0x28) // READ(10)
			{ 
				DWORD lba = (sptd->Cdb[2] << 24) | (sptd->Cdb[3] << 16) | (sptd->Cdb[4] << 8) | sptd->Cdb[5];
				if (CaptureCDIO)
				{
					LARGE_INTEGER start, end, freq;
					QueryPerformanceFrequency(&freq);
					QueryPerformanceCounter(&start);

					ret = NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

					QueryPerformanceCounter(&end);

					double ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
					logc(FOREGROUND_PINK, "READ(10) LBA: %u completed in %.3f ms, ScsiStatus=0x%02X\n", lba, ms, sptd->ScsiStatus);

					if (lba == 16)
					{
						logc(FOREGROUND_RED, "[Intercept] READ(10) LBA=%u, capturing real data %u bytes\n", lba, sptd->DataTransferLength);
						WriteToFile("sptd_LBA16.bin", (BYTE*)sptd->DataBuffer, sptd->DataTransferLength);
					}
					
					//SecuROM345Patching();
					GetKey();

					return ret;
				}
				else
				{
					DWORD xferLen = sptd->DataTransferLength;
					logc(FOREGROUND_RED, "[Intercept] READ(10) LBA=%u, returning blank %u bytes\n", lba, xferLen);

					bool IsSecuROM345 = false;
					
					if (!Securom7Confirmed)		// Don't bother keep doing this if we know we are handling SecuROM 7+
						IsSecuROM345 = SecuROM345Patching();

					if (sptd->DataBuffer && xferLen > 0) 
						memset(sptd->DataBuffer, 0, xferLen);  // return zeros
				
					if (lba == 16 && sptd->DataBuffer) // Primary Volume Descriptor (PVD)
					{
						logc(FOREGROUND_RED, "[Intercept] READ(10) LBA16 - injecting custom PVD\n");
						BYTE *pBuf = (BYTE*)sptd->DataBuffer;
						memcpy(&pBuf[1], hexstring("424541303101"), 6);
						memcpy(&pBuf[0x50], hexstring("F07E140000147EF0"), 8);
						memcpy(&pBuf[0x7BC], hexstring("21EC9511"), 4);
						if (IsSecuROM345)
						{
							logc(FOREGROUND_GREEN, "Patching for PVD for SecuROM 3/4/5 0000 \n");
							memcpy(&pBuf[0x7C0], hexstring("0000"), 2);   // <---- this is +7C0 check in the code - should probably be 0 or 08 00 for Securom 4/5 ?
						}
						else
						{
							logc(FOREGROUND_GREEN, "Patching for PVD for SecuROM 7+ %s \n", flip7C0 ? "0908" : "0000");
							memcpy(&pBuf[0x7C0], hexstring(flip7C0 ? "0908" : "0000"), 2); //memcpy(&pBuf[0x7C0], hexstring("0908"), 2);   // May need tweaking - but 0908 did not work for Football Manager 2008 - but does work for GTA SA
							flip7C0 = !flip7C0;
						}
						memcpy(&pBuf[0x7C8], hexstring("168A2855"), 4);
						memcpy(&pBuf[0x7D8], hexstring("0CEB936601"), 5);
						memcpy(&pBuf[0x7E4], hexstring("C309F845C309F845CB2B9866"), 12);
						memcpy(&pBuf[0x7F2], hexstring("0102F07E1401F07E1400B193D692"), 14);

						const char *Override7C0 = config.GetValue("Override7C0");
						if (Override7C0)	// Absolute Hack - but just in case we can't patch the 0x7C0 check properly for some games - allow user to override it
						{
							logc(FOREGROUND_YELLOW, "Overriding PVD +7C0 value with: %s\n", Override7C0);
							memcpy(&pBuf[0x7C0], hexstring(Override7C0), 2);
						}
						// strcpy((char*)&pBuf[0x28], "UKD_548520-001.001");		// Can put in the original disc's ID to get over the 1st CD Check
						/*
						FILE* f = fopen("sptd_LBA16.bin", "rb");
						fread(&pBuf[0], 1, 2048, f);
						fclose(f);*/
						// GetKey(true);
					}

					if (OutputBufferLength) 
					{
						IoStatusBlock->Status = STATUS_SUCCESS;
						IoStatusBlock->Information = xferLen;
					}
				}
				
				return STATUS_SUCCESS;
			}

			if (sptd && sptd->CdbLength >= 10 && sptd->Cdb[0] == 0xBE) // READ
			{
				logc(FOREGROUND_RED, "READ CD\n");
				DWORD lba = (sptd->Cdb[2] << 24) | (sptd->Cdb[3] << 16) | (sptd->Cdb[4] << 8) | sptd->Cdb[5];
				DWORD xferLen = (sptd->Cdb[6] << 16) | (sptd->Cdb[7] << 8) | sptd->Cdb[8];
				logc(FOREGROUND_BROWN, "  LBA: %u, TransferLength: %u sectors\n", lba, xferLen);
				if (false)
					ret = NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
				else
				{
					if (OutputBufferLength)
					{
						if (sptd->DataBuffer && xferLen > 0)
							memset(sptd->DataBuffer, 0, xferLen);  // return zeros

						//IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
						IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
						IoStatusBlock->Information = xferLen;
					}
					ret = STATUS_UNSUCCESSFUL;		// Making it successful actually breaks it ?
				}
				logc(FOREGROUND_PURPLE, "IOCTL %X (Handle: %X) - READ CD Ret: %X Status: %X (OutputBufferLength: %d)\n", IoControlCode, FileHandle, ret, IoStatusBlock->Status, OutputBufferLength);
				//LogKey("IOCTL_SCSI_PASS_THROUGH/Direct Out Buf:", (DWORD)OutputBuffer, OutputBufferLength);
				return ret;
			}

			if (sptd && sptd->CdbLength >= 6 && sptd->Cdb[0] == 0x00) // TEST UNIT READY
			{ 
				logc(FOREGROUND_RED, "[Intercept] TEST UNIT READY - faking success\n");

				// No data buffer to fill
				if (IoStatusBlock) 
				{
					IoStatusBlock->Status = STATUS_SUCCESS;
					IoStatusBlock->Information = 0; // no payload
				}

				return STATUS_SUCCESS; // pretend the device is ready
			}
		}

		ret = NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
		//logc(FOREGROUND_PURPLE, "IOCTL %X (Handle: %X) - IOCTL_SCSI_PASS_THROUGH Ret: %X (OutputBufferLength: %d)\n", IoControlCode, FileHandle, ret, OutputBufferLength);
		//LogKey("IOCTL_SCSI_PASS_THROUGH/Direct Out Buf:", (DWORD)OutputBuffer, OutputBufferLength);
		return ret;
	}
	else if (IoControlCode == IOCTL_DISK_PERFORMANCE)	// Can help make virtual drives work better with Securom // 0x70020
	{
		NTSTATUS ret = 0;//NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
		logc(FOREGROUND_CYAN, "IOCTL %X (Handle: %X) - IOCTL_DISK_PERFORMANCE Ret: %X (OutputBufferLength: %d)\n", IoControlCode, FileHandle, ret, OutputBufferLength);
		IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
		return STATUS_UNSUCCESSFUL;
	}
	else if (IoControlCode == IOCTL_STORAGE_CHECK_VERIFY)
	{
		if (CaptureCDIO)
		{
			logc(FOREGROUND_CYAN, "IOCTL %X (Handle: %X) - IOCTL_STORAGE_CHECK_VERIFY - Running Real\n", IoControlCode, FileHandle);
			return NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
		}
		else
		{
			logc(FOREGROUND_CYAN, "IOCTL %X (Handle: %X) - IOCTL_STORAGE_CHECK_VERIFY - Faking Success\n", IoControlCode, FileHandle);
			IoStatusBlock->Status = STATUS_SUCCESS;
			return STATUS_SUCCESS;
		}
	}
	else if (IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY)
	{
		if (CaptureCDIO)
		{
			logc(FOREGROUND_CYAN, "IOCTL %X (Handle: %X) - IOCTL_STORAGE_QUERY_PROPERTY - Dumping\n", IoControlCode, FileHandle);
			NTSTATUS ret = NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
			WriteToFile("IOCTL_STORAGE_QUERY_PROPERTY_InBuf.bin", (BYTE*)InputBuffer, InputBufferLength);
			WriteToFile("IOCTL_STORAGE_QUERY_PROPERTY_OutBuf.bin", (BYTE*)OutputBuffer, OutputBufferLength);
			return ret;
		}
		else
		{
			logc(FOREGROUND_CYAN, "IOCTL %X (Handle: %X) - IOCTL_STORAGE_QUERY_PROPERTY - Faking Success\n", IoControlCode, FileHandle);
			BYTE *daemon = hexstring("28000000A700000005000100000000004C000000750000007E000000020000002400000000000000058000325B00000044697363536F6674344D4947475033334B524C2020202020312E302044697363536F667420344D4947475033334B524C002020202000000000000000000000000000000000312E300000000000000000");
			memcpy(OutputBuffer, daemon, 0x80);
			IoStatusBlock->Status = STATUS_SUCCESS;
			return STATUS_SUCCESS;
		}
	}
	else if(IoControlCode == IOCTL_CDROM_READ_TOC)
	{
		if (CaptureCDIO)
		{
			logc(FOREGROUND_CYAN, "IOCTL %X (Handle: %X) - IOCTL_CDROM_READ_TOC - Dumping\n", IoControlCode, FileHandle);
			NTSTATUS ret = NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
			WriteToFile("IOCTL_CDROM_READ_TOC.bin", (BYTE*)OutputBuffer, OutputBufferLength);
			return ret;
		}
		else
		{
			logc(FOREGROUND_CYAN, "IOCTL %X (Handle: %X) - IOCTL_CDROM_READ_TOC - Faking Success\n", IoControlCode, FileHandle);
			BYTE* daemon = hexstring("28000000A700000005000100000000004C000000750000007E000000020000002400000000000000058000325B00000044697363536F6674344D4947475033334B524C2020202020312E302044697363536F667420344D4947475033334B524C002020202000000000000000000000000000000000312E300000000000000000");
			memcpy(OutputBuffer, daemon, 0x80);
			IoStatusBlock->Status = STATUS_SUCCESS;
			return STATUS_SUCCESS;
		}
	}
/*	else if (IoControlCode == IOCTL_STORAGE_MEDIA_REMOVAL)
	{
	}*/
	
	else if (IoControlCode == IOCTL_STORAGE_GET_MEDIA_TYPES_EX)
	{
		logc(FOREGROUND_CYAN, "IOCTL %X (Handle: %X) - IOCTL_STORAGE_GET_MEDIA_TYPES_EX - Faking Success\n", IoControlCode, FileHandle);
		IoStatusBlock->Status = STATUS_SUCCESS;
		return STATUS_SUCCESS;
	}
	else
	{
		if (IoControlCode == 0x22E81F)
		{
			logc(FOREGROUND_CYAN, "IOCTL %X (Handle: %X) - TAGES\n", IoControlCode, FileHandle);
			GetKey(true);
		}

		// Pass to original function
		NTSTATUS ret = NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
		if (IoControlCode != 0x500016)
			log("Returning Orig IoStatusBlock->Status Handle: %X ControlCode: %X Status: %X Ret: %X\n", (DWORD)FileHandle, IoControlCode, IoStatusBlock->Status, ret);

		//	log("NtDeviceIoControlFile_Orig Complete\n");
		return ret;
	}

	// log("Returning Overriden IoStatusBlock->Status Handle: %d ControlCode: %08X Status: %d\n", (DWORD)FileHandle, IoControlCode, IoStatusBlock->Status);
	return IoStatusBlock->Status;
}

void PrintCdbCommand(const BYTE* cdb, UCHAR cdbLen)
{
	if (cdbLen == 0) return;

	BYTE opcode = cdb[0];
	logc(FOREGROUND_RED, "Opcode 0x%02X: ", opcode);

	switch (opcode) {
	case 0x00: { // TEST UNIT READY
		logc(FOREGROUND_RED, "TEST UNIT READY\n");
		break;
	}
	case 0x03: { // REQUEST SENSE
		logc(FOREGROUND_RED, "REQUEST SENSE\n");
		BYTE allocLen = cdb[4];
		logc(FOREGROUND_BROWN, "  AllocationLength: %u\n", allocLen);
		break;
	}
	case 0x12: { // INQUIRY
		logc(FOREGROUND_RED, "INQUIRY\n");
		bool evpd = (cdb[1] & 0x01) != 0;
		BYTE pageCode = cdb[2];
		WORD allocLen = (cdb[3] << 8) | cdb[4];
		logc(FOREGROUND_BROWN, "  EVPD: %d, PageCode: 0x%02X, AllocationLength: %u\n",
			   evpd, pageCode, allocLen);
		break;
	}
	case 0x1A: { // MODE SENSE(6)
		logc(FOREGROUND_RED, "MODE SENSE(6)\n");
		BYTE pageCode = cdb[2] & 0x3F;
		BYTE subPage = cdb[3];
		BYTE allocLen = cdb[4];
		logc(FOREGROUND_BROWN, "  PageCode: 0x%02X, SubPage: 0x%02X, AllocationLength: %u\n",
			   pageCode, subPage, allocLen);
		break;
	}
	case 0x1B: { // START STOP UNIT
		logc(FOREGROUND_RED, "START STOP UNIT\n");
		bool loej = (cdb[4] & 0x02) != 0;
		bool start = (cdb[4] & 0x01) != 0;
		logc(FOREGROUND_BROWN, "  LoEj: %d, Start: %d\n", loej, start);
		break;
	}
	case 0x25: { // READ CAPACITY(10)
		logc(FOREGROUND_RED, "READ CAPACITY(10)\n");
		break; // response parsing happens from data buffer, not CDB
	}
	case 0x28: { // READ(10)
		logc(FOREGROUND_RED, "READ(10)\n");
		DWORD lba = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
		WORD xferLen = (cdb[7] << 8) | cdb[8];
		logc(FOREGROUND_BROWN, "  LBA: %u, TransferLength: %u blocks\n", lba, xferLen);
		break;
	}
	case 0x2A: { // WRITE(10)
		logc(FOREGROUND_RED, "WRITE(10)\n");
		DWORD lba = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
		WORD xferLen = (cdb[7] << 8) | cdb[8];
		logc(FOREGROUND_BROWN, "  LBA: %u, TransferLength: %u blocks\n", lba, xferLen);
		break;
	}
	case 0x2B: { // SEEK
		DWORD lba = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
		logc(FOREGROUND_RED, "SEEK LBA: %u\n", lba);
		break;
	}
	case 0x35: { // SYNCHRONIZE CACHE(10)
		logc(FOREGROUND_RED, "SYNCHRONIZE CACHE(10)\n");
		DWORD lba = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
		WORD numBlocks = (cdb[7] << 8) | cdb[8];
		logc(FOREGROUND_BROWN, "  LBA: %u, Blocks: %u\n", lba, numBlocks);
		break;
	}
	case 0x42: { // READ SUB-CHANNEL
		logc(FOREGROUND_RED, "READ SUB-CHANNEL\n");
		BYTE subQ = (cdb[2] & 0x40) != 0;
		BYTE subChannel = cdb[3] & 0x0F;
		WORD allocLen = (cdb[7] << 8) | cdb[8];
		logc(FOREGROUND_BROWN, "  SubQ: %d, SubChannel: %u, AllocationLength: %u\n",
			   subQ, subChannel, allocLen);
		break;
	}
	case 0x43: { // READ TOC/PMA/ATIP
		logc(FOREGROUND_RED, "READ TOC/PMA/ATIP\n");
		bool msf = (cdb[1] & 0x02) != 0;
		BYTE format = cdb[2];
		WORD allocLen = (cdb[7] << 8) | cdb[8];
		logc(FOREGROUND_BROWN, "  MSF: %d, Format: 0x%02X, AllocationLength: %u\n",
			   msf, format, allocLen);
		break;
	}
	case 0x46: { // GET CONFIGURATION
		logc(FOREGROUND_RED, "GET CONFIGURATION\n");
		WORD allocLen = (cdb[7] << 8) | cdb[8];
		logc(FOREGROUND_BROWN, "  AllocationLength: %u\n", allocLen);
		break;
	}
	case 0x4A: { // GET EVENT STATUS NOTIFICATION
		logc(FOREGROUND_RED, "GET EVENT STATUS NOTIFICATION\n");
		WORD allocLen = (cdb[7] << 8) | cdb[8];
		logc(FOREGROUND_BROWN, "  AllocationLength: %u\n", allocLen);
		break;
	}
	case 0x5A: { // MODE SENSE(10)
		logc(FOREGROUND_RED, "MODE SENSE(10)\n");
		BYTE pageCode = cdb[2] & 0x3F;
		BYTE subPage = cdb[3];
		WORD allocLen = (cdb[7] << 8) | cdb[8];
		logc(FOREGROUND_BROWN, "  PageCode: 0x%02X, SubPage: 0x%02X, AllocationLength: %u\n",
			   pageCode, subPage, allocLen);
		break;
	}
	case 0xA8: { // READ(12)
		logc(FOREGROUND_RED, "READ(12)\n");
		DWORD lba = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
		DWORD xferLen = (cdb[6] << 24) | (cdb[7] << 16) | (cdb[8] << 8) | cdb[9];
		logc(FOREGROUND_BROWN, "  LBA: %u, TransferLength: %u blocks\n", lba, xferLen);
		break;
	}
	case 0x88: { // READ(16)
		logc(FOREGROUND_RED, "READ(16)\n");
		ULONGLONG lba = ((ULONGLONG)cdb[2] << 56) | ((ULONGLONG)cdb[3] << 48) |
			((ULONGLONG)cdb[4] << 40) | ((ULONGLONG)cdb[5] << 32) |
			((ULONGLONG)cdb[6] << 24) | ((ULONGLONG)cdb[7] << 16) |
			((ULONGLONG)cdb[8] << 8) | (ULONGLONG)cdb[9];
		DWORD xferLen = (cdb[10] << 24) | (cdb[11] << 16) | (cdb[12] << 8) | cdb[13];
		logc(FOREGROUND_BROWN, "  LBA: %llu, TransferLength: %u blocks\n", lba, xferLen);
		break;
	}
	case 0x8A: { // WRITE(16)
		logc(FOREGROUND_RED, "WRITE(16)\n");
		ULONGLONG lba = ((ULONGLONG)cdb[2] << 56) | ((ULONGLONG)cdb[3] << 48) |
			((ULONGLONG)cdb[4] << 40) | ((ULONGLONG)cdb[5] << 32) |
			((ULONGLONG)cdb[6] << 24) | ((ULONGLONG)cdb[7] << 16) |
			((ULONGLONG)cdb[8] << 8) | (ULONGLONG)cdb[9];
		DWORD xferLen = (cdb[10] << 24) | (cdb[11] << 16) | (cdb[12] << 8) | cdb[13];
		logc(FOREGROUND_BROWN, "  LBA: %llu, TransferLength: %u blocks\n", lba, xferLen);
		break;
	}
	case 0x9E: { // Service Action in (16) like READ CAPACITY(16)
		BYTE serviceAction = cdb[1] & 0x1F;
		if (serviceAction == 0x10) {
			logc(FOREGROUND_RED, "READ CAPACITY(16)\n");
		}
		else {
			logc(FOREGROUND_RED, "SERVICE ACTION IN(16), action=0x%02X\n", serviceAction);
		}
		break;
	}
	case 0xBE: { // READ CD
		logc(FOREGROUND_RED, "READ CD\n");
		DWORD lba = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
		DWORD xferLen = (cdb[6] << 16) | (cdb[7] << 8) | cdb[8];
		logc(FOREGROUND_BROWN, "  LBA: %u, TransferLength: %u sectors\n", lba, xferLen);
		break;
	}
	default:
		logc(FOREGROUND_RED, "Unknown or unsupported opcode\n");
		break;
	}

	logc(FOREGROUND_BROWN, "");
	LogKey("Raw CDB: ", (DWORD)cdb, cdbLen);
}

