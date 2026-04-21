/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_ANALYSIS_ALBUM_ATTRIBUTE_SPEC_H
#define OHOS_MEDIA_ANALYSIS_ALBUM_ATTRIBUTE_SPEC_H

#include <cstddef>
#include <string>
#include <vector>

#include "analysis_album_attribute_const.h"

namespace OHOS::Media {
struct AnalysisAlbumAttributeSpec {
    std::string attr;
    std::vector<std::string> supportedTypes;
    bool enabled;
    size_t maxValueCount;
    size_t maxValueLength;
    bool allowEmptyValue;
    bool portraitOnly;
};

inline const AnalysisAlbumAttributeSpec ANALYSIS_ALBUM_NICK_NAME_SPEC = {
    ANALYSIS_ALBUM_ATTR_NICK_NAME,
    { ANALYSIS_ALBUM_OP_ADD, ANALYSIS_ALBUM_OP_REMOVE },
    true,
    ANALYSIS_ALBUM_MAX_OPERATION_VALUES,
    ANALYSIS_ALBUM_MAX_VALUE_LENGTH,
    false,
    true,
};

inline const AnalysisAlbumAttributeSpec *FindAnalysisAlbumAttributeSpec(const std::string &attr)
{
    if (attr == ANALYSIS_ALBUM_ATTR_NICK_NAME) {
        return &ANALYSIS_ALBUM_NICK_NAME_SPEC;
    }
    return nullptr;
}
} // namespace OHOS::Media

#endif // OHOS_MEDIA_ANALYSIS_ALBUM_ATTRIBUTE_SPEC_H
