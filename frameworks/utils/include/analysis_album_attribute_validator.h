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
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"

namespace OHOS::Media {

inline const std::string ANALYSIS_ALBUM_NAME_REGEX = R"([\.\\/:*?"'`<>|{}\[\]])";

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
    CHECK_AND_RETURN_RET(value.size() <= ANALYSIS_ALBUM_MAX_VALUE_LENGTH, false);
    CHECK_AND_RETURN_RET(!value.empty() || spec.allowEmptyValue, true);
    CHECK_AND_RETURN_RET(MediaFileUtils::CheckAlbumNameCharacter(value, ANALYSIS_ALBUM_NAME_REGEX) == E_OK
        || spec.supportSpecialSymbols, false);
    return true;
}

inline bool IsValidAnalysisAlbumValues(const std::vector<std::string> &values, const AnalysisAlbumAttributeSpec &spec)
{
    return values.size() <= ANALYSIS_ALBUM_MAX_OPERATION_VALUES &&
        std::all_of(values.begin(), values.end(),
        [&spec](const std::string &value) {
            return IsValidAnalysisAlbumValue(value, spec);
        });
}

inline bool IsSupportedAnalysisAlbumOperationType(const AnalysisAlbumAttributeSpec &spec, const std::string &type)
{
    return std::find(spec.supportedTypes.begin(), spec.supportedTypes.end(), type) != spec.supportedTypes.end();
}

inline bool IsSupportedAnalysisAlbumOperationValue(const AnalysisAlbumAttributeSpec &spec, const std::string &value)
{
    return std::find(spec.supportedValues.begin(), spec.supportedValues.end(), value) != spec.supportedValues.end();
}

inline bool IsSupportedAnalysisAlbumOperationValues(const AnalysisAlbumAttributeSpec &spec,
    const std::vector<std::string> &values)
{
    return values.size() <= spec.maxValueCount && values.size() > 0 &&(!spec.isSpecialValue ||
        std::all_of(values.begin(), values.end(),
        [&spec](const std::string &value) {
            return IsSupportedAnalysisAlbumOperationValue(spec, value);
        }));
}

inline int32_t ValidateAnalysisAlbumOperationProtocol(const std::string &attr, const std::string &type,
    const std::vector<std::string> &values)
{
    const AnalysisAlbumAttributeSpec *spec = FindAnalysisAlbumAttributeSpec(attr);
    CHECK_AND_RETURN_RET(IsValidAnalysisAlbumOperationType(type) && spec != nullptr &&
        IsValidAnalysisAlbumValues(values, *spec), E_INVALID_VALUES);
    return E_OK;
}

inline int32_t CheckAnalysisAlbumOperationSupport(const std::string &attr, const std::string &type,
    const std::vector<std::string> &values)
{
    const AnalysisAlbumAttributeSpec *spec = FindAnalysisAlbumAttributeSpec(attr);
    CHECK_AND_RETURN_RET(spec != nullptr, E_INVALID_VALUES);
    CHECK_AND_RETURN_RET(IsSupportedAnalysisAlbumOperationType(*spec, type), E_OPERATION_NOT_SUPPORT);
    CHECK_AND_RETURN_RET(IsSupportedAnalysisAlbumOperationValues(*spec, values), E_OPERATION_NOT_SUPPORT);
    return E_OK;
}

inline int32_t CheckAnalysisAlbumOperation(const std::string &attr, const std::string &type,
    const std::vector<std::string> &values)
{
    int32_t checkResult = ValidateAnalysisAlbumOperationProtocol(attr, type, values);
    CHECK_AND_RETURN_RET(checkResult == E_OK, checkResult);
    return CheckAnalysisAlbumOperationSupport(attr, type, values);
}

inline int32_t CheckAnalysisAlbumOperationWithClientNoOpGuard(const std::string &attr, const std::string &type,
    const std::vector<std::string> &values)
{
    CHECK_AND_RETURN_RET(!values.empty(), E_INVALID_VALUES);
    return CheckAnalysisAlbumOperation(attr, type, values);
}
} // namespace OHOS::Media

#endif // OHOS_MEDIA_ANALYSIS_ALBUM_ATTRIBUTE_VALIDATOR_H
