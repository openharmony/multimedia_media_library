/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "PhotoBurstOperation"

#include "photo_burst_operation.h"

#include <string>
#include <uuid.h>
#include <sstream>
#include <vector>
#include <numeric>
#include <algorithm>

#include "rdb_store.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "media_column.h"
#include "media_log.h"

namespace OHOS::Media {
PhotoBurstOperation &PhotoBurstOperation::SetTargetPhotoInfo(const PhotoAssetInfo &photoAssetInfo)
{
    this->photoAssetInfo_ = photoAssetInfo;
    this->photoAssetInfo_.burstGroupName = this->FindBurstGroupName(photoAssetInfo.displayName);
    return *this;
}

/**
 * @brief Find burstKey from the given albumId, only for BURST photo.
 * @return burstKey, if found; empty string, otherwise.
 */
std::string PhotoBurstOperation::FindBurstKey(const std::shared_ptr<MediaLibraryRdbStore> &rdbStore)
{
    return this->FindBurstKey(rdbStore, this->photoAssetInfo_);
}

/**
 * @brief Find burstKey from the given albumId, only for BURST photo.
 * @return burstKey, if found; empty string, otherwise.
 */
std::string PhotoBurstOperation::FindBurstKey(
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStore, const PhotoAssetInfo &photoAssetInfo)
{
    if (photoAssetInfo.ownerAlbumId <= 0 || photoAssetInfo.burstGroupName.empty() ||
        photoAssetInfo.subtype != static_cast<int32_t>(PhotoSubType::BURST) || rdbStore == nullptr) {
        return "";
    }
    std::string burstKey = this->QueryBurstKeyFromDB(rdbStore, photoAssetInfo);
    if (burstKey.empty()) {
        burstKey = this->GenerateUuid();
        MEDIA_INFO_LOG("Media_Operation: burstKey is empty, create a new one [%{public}s]. Object: %{public}s",
            burstKey.c_str(),
            photoAssetInfo.ToString().c_str());
    }
    return burstKey;
}

std::string PhotoBurstOperation::ToString(const std::vector<NativeRdb::ValueObject> &values)
{
    std::vector<std::string> result;
    for (auto &value : values) {
        std::string str;
        value.GetString(str);
        result.emplace_back(str + ", ");
    }
    return std::accumulate(result.begin(), result.end(), std::string());
}

/**
 * @brief generate a uuid
 *
 * @return std::string uuid with 37 characters
 */
std::string PhotoBurstOperation::GenerateUuid()
{
    uuid_t uuid;
    uuid_generate(uuid);
    char str[UUID_STR_LENGTH] = {};
    uuid_unparse(uuid, str);
    return str;
}

/**
 * @brief find prefix contains "_BURST" of displayName
 *
 * @return std::string prefix including "_BURST" of displayName
 */
std::string PhotoBurstOperation::FindBurstGroupName(const std::string &displayName)
{
    auto pos = displayName.find(this->TITLE_KEY_WORDS_OF_BURST);
    if (pos == std::string::npos) {
        MEDIA_ERR_LOG("Media_Operation: FindBurstGroupName: cannot find _BURST in displayName. displayName: %{public}s",
            displayName.c_str());
        return "";
    }
    return displayName.substr(0, std::min<int32_t>(pos, DISPLAY_NAME_PREFIX_LENGTH) + 1);
}

std::string PhotoBurstOperation::QueryBurstKeyFromDB(
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStore, const PhotoAssetInfo &photoAssetInfo)
{
    int32_t ownerAlbumId = photoAssetInfo.ownerAlbumId;
    std::string burstGroupName = photoAssetInfo.burstGroupName;
    // Avoid full table scan: if the burstGroupName is empty, return empty string.
    if (ownerAlbumId <= 0 || burstGroupName.empty() || rdbStore == nullptr) {
        MEDIA_ERR_LOG("Media_Operation: object invalid. Object: %{public}s", photoAssetInfo.ToString().c_str());
        return "";
    }
    std::string querySql = this->SQL_PHOTOS_TABLE_QUERY_BURST_KEY;
    std::string burstGroupNameCondition = burstGroupName + "%";
    const std::vector<NativeRdb::ValueObject> bindArgs = {ownerAlbumId, burstGroupNameCondition};
    auto resultSet = rdbStore->QuerySql(querySql, bindArgs);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_WARN_LOG("Media_Operation: resultSet is null or no data found! "
                       "querySql: %{public}s, bindArgs: %{public}s",
            querySql.c_str(),
            this->ToString(bindArgs).c_str());
        return "";
    }
    std::string burstKey = GetStringVal(PhotoColumn::PHOTO_BURST_KEY, resultSet);
    return burstKey;
}
}  // namespace OHOS::Media