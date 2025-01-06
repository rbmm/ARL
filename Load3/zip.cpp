#include "stdafx.h"
#include <compressapi.h>

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

HRESULT Unzip(_In_ LPCVOID CompressedData,
	_In_ ULONG CompressedDataSize,
	_Out_ PVOID* pUncompressedBuffer,
	_Out_ ULONG* pUncompressedDataSize)
{
	ULONG dwError;
	COMPRESSOR_HANDLE DecompressorHandle;

	if (NOERROR == (dwError = BOOL_TO_ERROR(CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, 0, &DecompressorHandle))))
	{
		SIZE_T UncompressedBufferSize = 0;
		PVOID UncompressedBuffer = 0;

		while (ERROR_INSUFFICIENT_BUFFER == (dwError = BOOL_TO_ERROR(Decompress(
			DecompressorHandle, CompressedData, CompressedDataSize,
			UncompressedBuffer, UncompressedBufferSize, &UncompressedBufferSize))) && !UncompressedBuffer)
		{
			if (!(UncompressedBuffer = VirtualAlloc(0, UncompressedBufferSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
			{
				dwError = ERROR_OUTOFMEMORY;
				break;
			}
		}

		if (NOERROR == dwError)
		{
			if (UncompressedBuffer)
			{
				*pUncompressedDataSize = (ULONG)UncompressedBufferSize;
				*pUncompressedBuffer = UncompressedBuffer, UncompressedBuffer = 0;
			}
			else
			{
				dwError = ERROR_INTERNAL_ERROR;
			}
		}

		if (UncompressedBuffer)
		{
			VirtualFree(UncompressedBuffer, 0, MEM_RELEASE);
		}

		CloseDecompressor(DecompressorHandle);
	}

	return HRESULT_FROM_WIN32(dwError);
}