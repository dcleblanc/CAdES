#include <Windows.h>
#include <bcrypt.h>
#include "../CAdESLib/Common.h"

#pragma comment(lib, "bcrypt.lib")

class AlgHandle
{
public:
    AlgHandle() : algHandle(nullptr) {}
    ~AlgHandle()
    {
        if (algHandle != nullptr)
            BCryptCloseAlgorithmProvider(algHandle, 0);
    }

    bool OpenSha256()
    {
        return Open(BCRYPT_SHA256_ALGORITHM);
    }

    bool Open(LPCWSTR algId)
    {
        return BCryptOpenAlgorithmProvider(&algHandle, algId, nullptr, 0) == ERROR_SUCCESS;
    }

    uint32_t GetHashLength()
    {
        return GetHashProperty(BCRYPT_HASH_LENGTH);
    }

    uint32_t GetHashObjectLength()
    {
        return GetHashProperty(BCRYPT_OBJECT_LENGTH);
    }

    uint32_t GetHashProperty(LPCWSTR propertyName)
    {
        DWORD dwSize = 0;
        ULONG dwCopied = 0;
        NTSTATUS stat = BCryptGetProperty(algHandle, propertyName, reinterpret_cast<PUCHAR>(&dwSize), sizeof(dwSize), &dwCopied, 0);
        return stat == ERROR_SUCCESS ? dwSize : 0;
    }

    operator BCRYPT_ALG_HANDLE() { return algHandle; }

private:
    BCRYPT_ALG_HANDLE algHandle;
};

class HashHandle
{
public:
    HashHandle(AlgHandle& _algHandle) : hHash(nullptr), sha256Size(32), algHandle(_algHandle) {}
    HashHandle() = delete;

    ~HashHandle()
    {
        if (hHash != nullptr)
            BCryptDestroyHash(hHash);
    }

    bool Create()
    {
        DWORD dwFlags = 0; // BCRYPT_HASH_REUSABLE_FLAG could be used in the future
        // Just hard code in sha256 sizes for now
        hashObj.clear();
        hashObj.resize(algHandle.GetHashObjectLength());

        NTSTATUS stat = BCryptCreateHash(algHandle, &hHash, &hashObj[0], static_cast<ULONG>(hashObj.size()), nullptr, 0, dwFlags);
        return (stat == ERROR_SUCCESS);
    }

    bool HashData(const uint8_t* pIn, uint32_t cbIn)
    {
        NTSTATUS stat = BCryptHashData(hHash, const_cast<PUCHAR>(pIn), cbIn, 0);
        return (stat == ERROR_SUCCESS);
    }

    bool Finish(std::vector<uint8_t>& hashValue)
    {
        hashValue.clear();
        hashValue.resize(algHandle.GetHashLength());

        NTSTATUS stat = BCryptFinishHash(hHash, &hashValue[0], static_cast<ULONG>(hashValue.size()), 0);
        return (stat == ERROR_SUCCESS);
    }

private:
    uint32_t sha256Size;
    std::vector<uint8_t> hashObj;
    BCRYPT_HASH_HANDLE hHash;
    AlgHandle& algHandle;
};

bool HashVector(AlgHandle& algHandle, const std::vector<uint8_t>& data, std::vector<uint8_t>& out)
{
    HashHandle hashHandle(algHandle);

    if (!hashHandle.Create())
        return false;

    if (!hashHandle.HashData(&data[0], static_cast<uint32_t>(data.size())))
        return false;

    return hashHandle.Finish(out);
}

static AlgHandle algHandleSha1;
static AlgHandle algHandleSha256;

bool HashVectorSha256(const std::vector<uint8_t>& data, std::vector<uint8_t>& out)
{
	// Warning, not thread safe, but we're currently single-threaded,
	// so open this just once.

	if (algHandleSha256 == nullptr)
	{
		if (!algHandleSha256.Open(BCRYPT_SHA256_ALGORITHM))
			return false;
	}

    return HashVector(algHandleSha256, data, out);
}

bool HashVectorSha1(const std::vector<uint8_t>& data, std::vector<uint8_t>& out)
{
	if (algHandleSha1 == nullptr)
	{
		if (!algHandleSha1.Open(BCRYPT_SHA1_ALGORITHM))
			return false;
	}

	return HashVector(algHandleSha1, data, out);
}

