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

#define MLOG_TAG "CloudAlbum"

#include "cloud_album_handler.h"

#include "medialibrary_unistore_manager.h"
#include "medialibrary_album_operations.h"
#include "photo_album_column.h"

using namespace std;

namespace OHOS {
namespace Media {

using ChangeType = DataShare::DataShareObserver::ChangeType;

static vector<string> GetIds(const CloudSyncHandleData &handleData)
{
    vector<string> fileIds;
    for (auto &uri : handleData.orgInfo.uris) {
        string uriString = uri.ToString();
        auto index = uriString.rfind('/');
        if (index == string::npos) {
            continue;
        }
        auto fileIdStr = uriString.substr(index + 1);
        fileIds.push_back(fileIdStr);
    }
    return fileIds;
}

static void UpdateCloudAlbum(const string &id, int32_t count)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Can not get rdbstore");
        return;
    }
    int changeRows = 0;
    NativeRdb::ValuesBucket valuesNew;
    valuesNew.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyTypes::TYPE_NEW));
    valuesNew.PutInt(PhotoAlbumColumns::ALBUM_COUNT, count);
    NativeRdb::RdbPredicates rdbPredicates(PhotoAlbumColumns::TABLE);
    rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, id);
    rdbStore->Update(changeRows, valuesNew, rdbPredicates);
    if (changeRows < 0) {
        MEDIA_ERR_LOG("Failed to update cloudAlbum , ret = %{public}d", changeRows);
    }
}
static int32_t GetCloudAlbumCount(const string &id)
{
    const std::vector<std::string> columnInfo;

    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, id);
    predicates.And()->EqualTo(PhotoColumn::MEDIA_HIDDEN, 0);
    predicates.And()->EqualTo(PhotoColumn::MEDIA_DATE_TRASHED, 0);
    predicates.And()->EqualTo(PhotoColumn::PHOTO_CLEAN_FLAG,
        to_string(static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN)));

    auto resultSet = MediaLibraryRdbStore::Query(predicates, columnInfo);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("MediaLibraryRdbStore::Query error\n");
        return E_HAS_DB_ERROR;
    }

    int32_t rowCount;
    auto ret = resultSet->GetRowCount(rowCount);
    if (ret != 0) {
        MEDIA_ERR_LOG("result set get row count err %{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    return rowCount;
}

void DeleteOrUpdateCloudAlbums(const vector<string> &ids)
{
    for (const auto &id : ids) {
        auto count = GetCloudAlbumCount(id);
        if (count == 0) {
            NativeRdb::RdbPredicates rdbPredicate(PhotoAlbumColumns::TABLE);
            rdbPredicate.EqualTo(PhotoAlbumColumns::ALBUM_ID, id);
            if (MediaLibraryAlbumOperations::DeletePhotoAlbum(rdbPredicate) > 0) {
                MEDIA_DEBUG_LOG("delete Album {%{public}s} succ", id.c_str());
            } else {
                MEDIA_DEBUG_LOG("delete Album {%{public}s} fail", id.c_str());
            }
        } else {
            MEDIA_DEBUG_LOG("Album {%{public}s} not empty, count %{public}d", id.c_str(), count);
            UpdateCloudAlbum(id, count);
        }
    }
}

void CloudAlbumHandler::Handle(const CloudSyncHandleData &handleData)
{
    if (handleData.orgInfo.type == ChangeType::DELETE) {
        vector<string> fileIds;
        fileIds = GetIds(handleData);
        DeleteOrUpdateCloudAlbums(fileIds);
    }
    if (nextHandler_ != nullptr) {
        nextHandler_->Handle(handleData);
    }
}

} //namespace Media
} //namespace OHOS
