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
#define MLOG_TAG "PhotoAlbumMergeOperation"

#include "photo_album_merge_operation.h"

#include <algorithm>
#include <numeric>

#include "media_log.h"
#include "medialibrary_errno.h"
#include "userfile_manager_types.h"
#include "media_file_utils.h"
#include "result_set_utils.h"

namespace OHOS::Media {
PhotoAlbumMergeOperation &PhotoAlbumMergeOperation::SetRdbStore(
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStorePtr)
{
    this->rdbStorePtr_ = rdbStorePtr;
    return *this;
}

int32_t PhotoAlbumMergeOperation::MergeAlbum(const int32_t &oldAlbumId, const int32_t &newAlbumId)
{
    bool isSuccessed = true;
    isSuccessed = isSuccessed && this->DeleteDuplicateRelationshipInPhotoMap(oldAlbumId, newAlbumId) == NativeRdb::E_OK;
    isSuccessed = isSuccessed && this->UpdateRelationshipInPhotoMap(oldAlbumId, newAlbumId) == NativeRdb::E_OK;
    isSuccessed = isSuccessed && this->UpdateRelationshipInPhotos(oldAlbumId, newAlbumId) == NativeRdb::E_OK;
    isSuccessed = isSuccessed && this->DeleteOldAlbum(oldAlbumId) == NativeRdb::E_OK;
    return isSuccessed ? NativeRdb::E_OK : NativeRdb::E_ERROR;
}

std::string PhotoAlbumMergeOperation::ToString(const std::vector<NativeRdb::ValueObject> &values)
{
    std::vector<std::string> result;
    std::string str;
    for (auto &value : values) {
        value.GetString(str);
        result.emplace_back(str + ", ");
    }
    return std::accumulate(result.begin(), result.end(), std::string());
}

int32_t PhotoAlbumMergeOperation::DeleteDuplicateRelationshipInPhotoMap(
    const int32_t &oldAlbumId, const int32_t &newAlbumId)
{
    bool isInvalid = this->rdbStorePtr_ == nullptr || oldAlbumId <= 0 || newAlbumId <= 0;
    CHECK_AND_RETURN_RET(!isInvalid, NativeRdb::E_ERROR);

    std::string sql = this->SQL_PHOTO_MAP_DUPLICATE_RELATIONSHIP_DELETE;
    const std::vector<NativeRdb::ValueObject> bindArgs = {oldAlbumId, newAlbumId};
    int32_t ret = this->rdbStorePtr_->ExecuteSql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
        "Media_Operation: Failed to exec: %{public}s, bindArgs: %{public}s", sql.c_str(),
        this->ToString(bindArgs).c_str());
    return NativeRdb::E_OK;
}

int32_t PhotoAlbumMergeOperation::UpdateRelationshipInPhotoMap(const int32_t &oldAlbumId, const int32_t &newAlbumId)
{
    bool isInvalid = this->rdbStorePtr_ == nullptr || oldAlbumId <= 0 || newAlbumId <= 0;
    CHECK_AND_RETURN_RET(!isInvalid, NativeRdb::E_ERROR);

    std::string sql = this->SQL_PHOTO_MAP_MOVE_RELATIONSHIP_UPDATE;
    const std::vector<NativeRdb::ValueObject> bindArgs = {newAlbumId, oldAlbumId, newAlbumId};
    int32_t ret = this->rdbStorePtr_->ExecuteSql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
        "Media_Operation: Failed to exec: %{public}s, bindArgs: %{public}s", sql.c_str(),
        this->ToString(bindArgs).c_str());
    return NativeRdb::E_OK;
}

int32_t PhotoAlbumMergeOperation::UpdateRelationshipInPhotos(const int32_t &oldAlbumId, const int32_t &newAlbumId)
{
    bool isInvalid = this->rdbStorePtr_ == nullptr || oldAlbumId <= 0 || newAlbumId <= 0;
    CHECK_AND_RETURN_RET(!isInvalid, NativeRdb::E_ERROR);

    std::string sql = this->SQL_PHOTOS_MOVE_RELATIONSHIP_UPDATE;
    const std::vector<NativeRdb::ValueObject> bindArgs = {newAlbumId, oldAlbumId, newAlbumId};
    int32_t ret = this->rdbStorePtr_->ExecuteSql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
        "Media_Operation: Failed to exec: %{public}s, bindArgs: %{public}s", sql.c_str(),
        this->ToString(bindArgs).c_str());
    return NativeRdb::E_OK;
}

int32_t PhotoAlbumMergeOperation::DeleteOldAlbum(const int32_t &oldAlbumId)
{
    bool isInvalid = this->rdbStorePtr_ == nullptr || oldAlbumId <= 0;
    CHECK_AND_RETURN_RET(!isInvalid, NativeRdb::E_ERROR);

    std::string sql = this->SQL_PHOTO_ALBUM_DELETE;
    const std::vector<NativeRdb::ValueObject> bindArgs = {oldAlbumId};
    int32_t ret = this->rdbStorePtr_->ExecuteSql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
        "Media_Operation: Failed to exec: %{public}s, bindArgs: %{public}s", sql.c_str(),
        this->ToString(bindArgs).c_str());
    return NativeRdb::E_OK;
}
}  // namespace OHOS::Media