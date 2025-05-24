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

#ifndef INTERFACES_INNERKITS_NATIVE_INCLUDE_PHOTO_ASSERT_CUSTOM_RECORDS_H_
#define INTERFACES_INNERKITS_NATIVE_INCLUDE_PHOTO_ASSERT_CUSTOM_RECORDS_H_

#include <string>
#include <vector>

#include "medialibrary_type_const.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class PhotoAssetCustomRecord {
public:
    EXPORT PhotoAssetCustomRecord();
    EXPORT virtual ~PhotoAssetCustomRecord();

    EXPORT void SetFileId(const int32_t fileId);
    EXPORT void SetShareCount(const int32_t shareCount);
    EXPORT void SetLcdJumpCount(const int32_t lcdJumpCount);
    EXPORT void SetResultNapiType(const ResultNapiType type);

    EXPORT int32_t GetFileId() const;
    EXPORT int32_t GetShareCount() const;
    EXPORT int32_t GetLcdJumpCount() const;
    EXPORT ResultNapiType GetResultNapiType() const;
    EXPORT int32_t GetCount() const;

private:
    int32_t fileId_;
    int32_t shareCount_;
    int32_t lcdJumpCount_;

    ResultNapiType resultNapiType_;
    int32_t count_;
};
} // namespace Media
} // namespace OHOS

#endif  // INTERFACES_INNERKITS_NATIVE_INCLUDE_PHOTO_ASSERT_CUSTOM_RECORDS_H_
