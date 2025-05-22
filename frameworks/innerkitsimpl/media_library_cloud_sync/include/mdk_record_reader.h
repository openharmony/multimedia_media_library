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

#ifndef OHOS_MEDIA_CLOUD_SYNC_MDK_RECORD_READER_H
#define OHOS_MEDIA_CLOUD_SYNC_MDK_RECORD_READER_H

#include <map>
#include <vector>

#include "mdk_record.h"
#include "mdk_reference.h"
#include "mdk_database.h"

namespace OHOS::Media::CloudSync {
class MDKRecordReader {
public:
    std::optional<MDKAsset> GetAssetValue(const std::map<std::string, MDKRecordField> &fields, const std::string &key) const
    {
        std::optional<MDKAsset> valueOpt;
        auto it = fields.find(key);
        if (it == fields.end()) {
            return valueOpt;
        }
        MDKAsset value;
        MDKLocalErrorCode errorCode = it->second.GetAsset(value);
        if (errorCode != MDKLocalErrorCode::NO_ERROR) {
            return valueOpt;
        }
        return value;
    }
    std::optional<std::string> GetStringValue(const std::map<std::string, MDKRecordField> &fields, const std::string &key) const
    {
        std::optional<std::string> valueOpt;
        auto it = fields.find(key);
        if (it == fields.end()) {
            return valueOpt;
        }
        std::string value;
        MDKLocalErrorCode errorCode = it->second.GetString(value);
        if (errorCode != MDKLocalErrorCode::NO_ERROR) {
            return valueOpt;
        }
        return value;
    }
    std::optional<int64_t> GetLongValue(const std::map<std::string, MDKRecordField> &fields, const std::string &key) const
    {
        std::optional<int64_t> valueOpt;
        auto it = fields.find(key);
        if (it == fields.end()) {
            return valueOpt;
        }
        int64_t value;
        MDKLocalErrorCode errorCode = it->second.GetLong(value);
        if (errorCode != MDKLocalErrorCode::NO_ERROR) {
            return valueOpt;
        }
        return value;
    }
    std::optional<int32_t> GetIntValue(const std::map<std::string, MDKRecordField> &fields, const std::string &key) const
    {
        std::optional<int32_t> resultOpt;
        std::optional<int64_t> valueOpt = this->GetLongValue(fields, key);
        if (valueOpt) {
            resultOpt = static_cast<int32_t>(valueOpt.value());
        }
        return resultOpt;
    }
    std::optional<bool> GetBoolValue(const std::map<std::string, MDKRecordField> &fields, const std::string &key) const
    {
        std::optional<bool> valueOpt;
        auto it = fields.find(key);
        if (it == fields.end()) {
            return valueOpt;
        }
        bool value;
        MDKLocalErrorCode errorCode = it->second.GetBool(value);
        if (errorCode != MDKLocalErrorCode::NO_ERROR) {
            return valueOpt;
        }
        return value;
    }
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_MDK_RECORD_READER_H