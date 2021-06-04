// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

template <typename T>
size_t GetEncodedSize(std::vector<T> &in) // Non-const reference, because EncodedSize will set cbData
{
	size_t ret = GetDataSize(in);

	if (ret == 0)
		return 2;

	return ret;
}

template <typename T>
size_t GetDataSize(std::vector<T> &in)
{
	size_t ret = 0;
	for(auto i: in)
	{ 
		ret += i.EncodedSize();
	}
	return ret;
}