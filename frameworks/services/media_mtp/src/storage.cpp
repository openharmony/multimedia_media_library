/*
* Copyright (C) 2022 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "storage.h"

namespace OHOS {
namespace Media {
Storage::Storage()
{
}

Storage::~Storage()
{
}

uint32_t Storage::GetStorageID()
{
    return mStorageID;
}

uint16_t Storage::GetStorageType()
{
    return mStorageType;
}

uint16_t Storage::GetFilesystemType()
{
    return mFileSystemType;
}

uint16_t Storage::GetAccessCapability()
{
    return mAccessCapability;
}

uint64_t Storage::GetMaxCapacity()
{
    return mMaxCapacity;
}

uint64_t Storage::GetFreeSpaceInBytes()
{
    return mFreeSpaceInBytes;
}

uint32_t Storage::GetFreeSpaceInObjects()
{
    return mFreeSpaceInObjects;
}

std::string Storage::GetStorageDescription()
{
    return mStorageDescription;
}

std::string Storage::GetVolumeIdentifier()
{
    return mVolumeIdentifier;
}
} // namespace Media
} // namespace OHOS