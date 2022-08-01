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

#include "dir_asset.h"

#include "medialibrary_type_const.h"

using namespace std;

namespace OHOS {
namespace Media {
DirAsset::DirAsset()
{
    dirType_ = DEFAULT_DIR_TYPE;
    mediaTypes_ = DEFAULT_STRING_MEDIA_TYPE;
    directory_ = DEFAULT_DIRECTORY;
    extensions_ = DEFAULT_EXTENSION;
};
DirAsset::~DirAsset() = default;

void DirAsset::SetDirType(const int32_t dirtype)
{
    dirType_ = dirtype;
}

void DirAsset::SetDirectory(const string directory)
{
    directory_ = directory;
}

void DirAsset::SetExtensions(const string extensions)
{
    extensions_ = extensions;
}

void DirAsset::SetMediaTypes(const string mediaTypes)
{
    mediaTypes_ = mediaTypes;
}

int32_t DirAsset::GetDirType() const
{
    return dirType_;
}

string DirAsset::GetMediaTypes() const
{
    return mediaTypes_;
}

string DirAsset::GetDirectory() const
{
    return directory_;
}

string DirAsset::GetExtensions() const
{
    return extensions_;
}
}  // namespace Media
}  // namespace OHOS
