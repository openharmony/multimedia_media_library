/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "photo_asset_custom_record.h"

#include "media_file_utils.h"
#include "medialibrary_type_const.h"

namespace OHOS {
namespace Media {
PhotoAssetCustomRecord::PhotoAssetCustomRecord()
{
    fileId_ = DEFAULT_FILE_ID;
    shareCount_ = DEFAULT_SHARE_COUNT;
    lcdJumpCount_ = DEFAULT_LCD_JUMO_COUNT;
    resultNapiType_ = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    count_ = DEFAULT_COUNT;
}

PhotoAssetCustomRecord::~PhotoAssetCustomRecord() = default;

void PhotoAssetCustomRecord::SetFileId(const int32_t fileId)
{
    fileId_ = fileId;
}

void PhotoAssetCustomRecord::SetShareCount(const int32_t shareCount)
{
    shareCount_ = shareCount;
}

void PhotoAssetCustomRecord::SetLcdJumpCount(const int32_t lcdJumpCount)
{
    lcdJumpCount_ = lcdJumpCount;
}

void PhotoAssetCustomRecord::SetResultNapiType(const ResultNapiType type)
{
    resultNapiType_ = type;
}

int32_t PhotoAssetCustomRecord::GetFileId() const
{
    return fileId_;
}

int32_t PhotoAssetCustomRecord::GetShareCount() const
{
    return shareCount_;
}

int32_t PhotoAssetCustomRecord::GetLcdJumpCount() const
{
    return lcdJumpCount_;
}

ResultNapiType PhotoAssetCustomRecord::GetResultNapiType() const
{
    return resultNapiType_;
}

int32_t PhotoAssetCustomRecord::GetCount() const
{
    return count_;
}
} // namespace Media
} // namespace OHOS 