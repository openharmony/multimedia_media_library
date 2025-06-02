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
#define MLOG_TAG "Media_Client"

#include "mdk_record_reader.h"

#include <string>

#include "media_log.h"

namespace OHOS::Media::CloudSync {
std::optional<MDKAsset> MDKRecordReader::GetAssetValue(
    const std::map<std::string, MDKRecordField> &fields, const std::string &key) const
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
std::optional<std::string> MDKRecordReader::GetStringValue(
    const std::map<std::string, MDKRecordField> &fields, const std::string &key) const
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
std::optional<int64_t> MDKRecordReader::GetLongValue(
    const std::map<std::string, MDKRecordField> &fields, const std::string &key) const
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
std::optional<int32_t> MDKRecordReader::GetIntValue(
    const std::map<std::string, MDKRecordField> &fields, const std::string &key) const
{
    std::optional<int32_t> resultOpt;
    std::optional<int64_t> valueOpt = this->GetLongValue(fields, key);
    if (valueOpt) {
        resultOpt = static_cast<int32_t>(valueOpt.value());
    }
    return resultOpt;
}
std::optional<bool> MDKRecordReader::GetBoolValue(
    const std::map<std::string, MDKRecordField> &fields, const std::string &key) const
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
}  // namespace OHOS::Media::CloudSync