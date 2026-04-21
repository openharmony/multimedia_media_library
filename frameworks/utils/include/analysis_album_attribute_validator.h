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

#ifndef OHOS_MEDIA_ANALYSIS_ALBUM_ATTRIBUTE_VALIDATOR_H
#define OHOS_MEDIA_ANALYSIS_ALBUM_ATTRIBUTE_VALIDATOR_H

#include <algorithm>
#include <string>
#include <vector>

#include "analysis_album_attribute_const.h"
#include "analysis_album_attribute_spec.h"
#include "medialibrary_errno.h"

namespace OHOS::Media {
inline bool IsValidAnalysisAlbumAttribute(const std::string &attr)
{
    return FindAnalysisAlbumAttributeSpec(attr) != nullptr;
}

inline bool IsValidAnalysisAlbumOperationType(const std::string &type)
{
    return type == ANALYSIS_ALBUM_OP_ADD || type == ANALYSIS_ALBUM_OP_REMOVE || type == ANALYSIS_ALBUM_OP_UPDATE;
}

inline bool IsValidAnalysisAlbumValue(const std::string &value, const AnalysisAlbumAttributeSpec &spec)
{
    return value.size() <= spec.maxValueLength && (spec.allowEmptyValue || !value.empty());
}

inline bool IsValidAnalysisAlbumValues(const std::vector<std::string> &values, const AnalysisAlbumAttributeSpec &spec)
{
    return values.size() <= spec.maxValueCount && std::all_of(values.begin(), values.end(),
        [&spec](const std::string &value) {
            return IsValidAnalysisAlbumValue(value, spec);
        });
}

inline bool IsSupportedAnalysisAlbumOperationType(const AnalysisAlbumAttributeSpec &spec, const std::string &type)
{
    return std::find(spec.supportedTypes.begin(), spec.supportedTypes.end(), type) != spec.supportedTypes.end();
}

inline int32_t ValidateAnalysisAlbumOperationProtocol(const std::string &attr, const std::string &type,
    const std::vector<std::string> &values)
{
    const AnalysisAlbumAttributeSpec *spec = FindAnalysisAlbumAttributeSpec(attr);
    if (!IsValidAnalysisAlbumOperationType(type) || spec == nullptr || !IsValidAnalysisAlbumValues(values, *spec)) {
        return E_INVALID_VALUES;
    }
    return E_OK;
}

inline int32_t CheckAnalysisAlbumOperationSupport(const std::string &attr, const std::string &type)
{
    const AnalysisAlbumAttributeSpec *spec = FindAnalysisAlbumAttributeSpec(attr);
    if (spec == nullptr) {
        return E_INVALID_VALUES;
    }
    if (spec->enabled && IsSupportedAnalysisAlbumOperationType(*spec, type)) {
        return E_OK;
    }
    return E_OPERATION_NOT_SUPPORT;
}

inline int32_t CheckAnalysisAlbumOperation(const std::string &attr, const std::string &type,
    const std::vector<std::string> &values)
{
    int32_t checkResult = ValidateAnalysisAlbumOperationProtocol(attr, type, values);
    if (checkResult != E_OK) {
        return checkResult;
    }
    return CheckAnalysisAlbumOperationSupport(attr, type);
}
} // namespace OHOS::Media

#endif // OHOS_MEDIA_ANALYSIS_ALBUM_ATTRIBUTE_VALIDATOR_H
