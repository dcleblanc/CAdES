#include "../CAdESLib/Common.h"
#include "CertToXml.h"

std::wostream& ctx::operator<<(std::wostream& os, const std::vector<std::byte>& data)
{
    for (size_t pos = 0; pos < data.size(); ++pos)
    {
        os << std::setfill(L'0') << std::setw(2) << std::hex << (unsigned short)data[pos];
    }

    return os;
}

void ctx::xValidity::ConvertTime(const Time & t, std::wstring & out)
{
    // The incoming data will be in the form of either:
    // YYYYMMDDHHMMSSZ - 15 chars, GeneralizedTime (unusual)
    // YYMMDDHHMMSSZ   - 13 chars, UTCTime
    // Output will be in this format:
    // The dateTime is specified in the following form "YYYY-MM-DDThh:mm:ss" where:

    TimeType type = t.GetType();
    const std::wstring& time = t.GetValueW();

    out.clear();
    size_t pos = 0;

    if (type == TimeType::GeneralizedTime)
    {
        // 4 character year
        out = time.substr(pos, 4);
        out += L'-';
        pos = 4;
    }
    else if (type == TimeType::UTCTime)
    {
        std::wstring yy = time.substr(pos, 2);
        wchar_t decade = yy[0];

        if (decade >= L'5' && decade <= L'9')
        {
            out = L"19";
        }
        else
        {
            out = L"20";
        }

        out += yy;
        out += L'-';
        pos = 2;
    }
    else
    {
        assert(false);
        return;
    }

    // Now that the year is sorted out, get the rest
    // Month
    out += time.substr(pos, 2);
    out += L'-';
    pos += 2;
    // Day
    out += time.substr(pos, 2);
    out += L'T';
    pos += 2;
    // Hours
    out += time.substr(pos, 2);
    out += L':';
    pos += 2;
    // Minutes
    out += time.substr(pos, 2);
    out += L':';
    pos += 2;
    // Seconds
    out += time.substr(pos, 2);
    out += L'Z';
}

void ctx::xDirectoryString::Convert(const DirectoryString & ds)
{
    DirectoryStringType dsType = ds.GetType();

    switch (dsType)
    {
    case DirectoryStringType::Error:
    case DirectoryStringType::NotSet:
        return;

        // Not sure how often we'll encounter these
    case DirectoryStringType::BMPString:
        assert(false);
        return;
    default:
        // Get the value data out of the AnyType, and assign it to the string
        break;
    }

    const AnyType& any = ds.GetValue();
    if (!any.ToString(directoryString))
    {
        assert(false);
        return;
    }
}

