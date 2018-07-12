#include "Common.h"

void ctx::xValidity::ConvertTime(const Time & t, std::string & out)
{
    // The incoming data will be in the form of either:
    // YYYYMMDDHHMMSSZ - 15 chars, GeneralizedTime (unusual)
    // YYMMDDHHMMSSZ   - 13 chars, UTCTime
    // Output will be in this format:
    // The dateTime is specified in the following form "YYYY-MM-DDThh:mm:ss" where:

    TimeType type = t.GetType();
    const std::string& time = t.GetValue();

    out.clear();
    size_t pos = 0;

    if (type == TimeType::GeneralizedTime)
    {
        // 4 character year
        out = time.substr(pos, 4);
        out += '-';
        pos = 4;
    }
    else if (type == TimeType::UTCTime)
    {
        std::string yy = time.substr(pos, 2);
        char decade = yy[0];

        if (decade >= '5' && decade <= '9')
        {
            out = "19";
        }
        else
        {
            out = "20";
        }

        out += yy;
        out += '-';
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
    out += '-';
    pos += 2;
    // Day
    out += time.substr(pos, 2);
    out += 'T';
    pos += 2;
    // Hours
    out += time.substr(pos, 2);
    out += ':';
    pos += 2;
    // Minutes
    out += time.substr(pos, 2);
    out += ':';
    pos += 2;
    // Seconds
    out += time.substr(pos, 2);
    out += 'Z';
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

