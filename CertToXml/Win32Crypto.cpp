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

    unsigned long GetHashLength()
    {
        return GetHashProperty(BCRYPT_HASH_LENGTH);
    }

    unsigned long GetHashObjectLength()
    {
        return GetHashProperty(BCRYPT_OBJECT_LENGTH);
    }

    unsigned long GetHashProperty(LPCWSTR propertyName)
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

    bool HashData(const unsigned char* pIn, unsigned long cbIn)
    {
        NTSTATUS stat = BCryptHashData(hHash, const_cast<PUCHAR>(pIn), cbIn, 0);
        return (stat == ERROR_SUCCESS);
    }

    bool Finish(std::vector<unsigned char>& hashValue)
    {
        hashValue.clear();
        hashValue.resize(algHandle.GetHashLength());

        NTSTATUS stat = BCryptFinishHash(hHash, &hashValue[0], static_cast<ULONG>(hashValue.size()), 0);
        return (stat == ERROR_SUCCESS);
    }

private:
    unsigned long sha256Size;
    std::vector<unsigned char> hashObj;
    BCRYPT_HASH_HANDLE hHash;
    AlgHandle& algHandle;
};

bool HashVector(LPCWSTR algId, const std::vector<unsigned char>& data, std::vector<unsigned char>& out)
{
    AlgHandle algHandle;
    HashHandle hashHandle(algHandle);

    if (!algHandle.Open(algId))
        return false;

    if (!hashHandle.Create())
        return false;

    if (!hashHandle.HashData(&data[0], static_cast<unsigned long>(data.size())))
        return false;

    return hashHandle.Finish(out);
}

bool HashVectorSha256(const std::vector<unsigned char>& data, std::vector<unsigned char>& out)
{
    return HashVector(BCRYPT_SHA256_ALGORITHM, data, out);
}

bool HashVectorSha1(const std::vector<unsigned char>& data, std::vector<unsigned char>& out)
{
    return HashVector(BCRYPT_SHA1_ALGORITHM, data, out);
}

