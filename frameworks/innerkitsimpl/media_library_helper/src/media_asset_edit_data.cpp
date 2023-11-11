/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaAssetEditData"

#include "media_asset_edit_data.h"

using namespace std;

namespace OHOS::Media {
string MediaAssetEditData::GetCompatibleFormat() const
{
    return compatibleFormat_;
}

void MediaAssetEditData::SetCompatibleFormat(const string& compatibleFormat)
{
    compatibleFormat_ = compatibleFormat;
}

string MediaAssetEditData::GetFormatVersion() const
{
    return formatVersion_;
}

void MediaAssetEditData::SetFormatVersion(const string& formatVersion)
{
    formatVersion_ = formatVersion;
}

string MediaAssetEditData::GetData() const
{
    return data_;
}

void MediaAssetEditData::SetData(const string& data)
{
    data_ = data;
}
} // namespace OHOS::Media