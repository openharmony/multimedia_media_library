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

#include "analysis_handler.h"

#include "medialibrary_unistore_manager.h"
#include "medialibrary_rdb_utils.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "result_set_utils.h"
#include "vision_column.h"
#include "medialibrary_album_operations.h"

using namespace std;

namespace OHOS {
namespace Media {

using ChangeType = DataShare::DataShareObserver::ChangeType;

static vector<string> GetFileIds(const CloudSyncHandleData &handleData)
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

static shared_ptr<ResultSet> GetUpdateAnalysisAlbumsInfo(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const vector<string> &fileIds)
{
    vector<string> columns = {
        ANALYSIS_PHOTO_MAP_TABLE + "." + PhotoMap::ALBUM_ID,
        ANALYSIS_PHOTO_MAP_TABLE + "." + PhotoMap::ASSET_ID
    };
    RdbPredicates predicates(ANALYSIS_PHOTO_MAP_TABLE);
    predicates.In(PhotoMap::ASSET_ID, fileIds);

    return rdbStore->Query(predicates, columns);
}

static list<Uri> UpdateAnalysisAlbumsForCloudSync(const shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const shared_ptr<ResultSet> &resultSet, const vector<string> &fileIds)
{
    vector<string> albumIds;

    while (resultSet->GoToNextRow() == E_OK) {
        albumIds.push_back(get<string>(ResultSetUtils::GetValFromColumn(
            ANALYSIS_PHOTO_MAP_TABLE + "." + PhotoMap::ALBUM_ID, resultSet, TYPE_STRING)));
    }
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore, albumIds, fileIds);

    list<Uri> sendUris;
    for (auto albumId : albumIds) {
        sendUris.push_back(Uri(PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX + albumId));
    }

    return sendUris;
}

static void AddNewNotify(CloudSyncHandleData &handleData, const list<Uri> &sendUris)
{
    if (sendUris.size() <= 0) {
        return;
    }
    ChangeType changeType = static_cast<ChangeType>(NotifyType::NOTIFY_UPDATE);
    if (handleData.notifyInfo.find(changeType) == handleData.notifyInfo.end()) {
        handleData.notifyInfo[changeType] = sendUris;
    } else {
        handleData.notifyInfo[changeType].insert(
            handleData.notifyInfo[changeType].end(), sendUris.begin(), sendUris.end());
    }
    return;
}

void AnalysisHandler::Handle(const CloudSyncHandleData &handleData)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Can not get rdbstore");
        return;
    }

    vector<string> fileIds;
    if (handleData.orgInfo.type == ChangeType::OTHER) {
        MEDIA_INFO_LOG("Update the AnalysisAlbum for ChangeType being OTHER");
        MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore);
    } else {
        fileIds = GetFileIds(handleData);
    }

    CloudSyncHandleData newHandleData = handleData;
    if (!fileIds.empty()) {
        shared_ptr<ResultSet> resultSet = GetUpdateAnalysisAlbumsInfo(rdbStore, fileIds);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("Failed query AnalysisAlbum");
            return;
        };
        int32_t count = -1;
        int32_t err = resultSet->GetRowCount(count);
        if (err != E_OK) {
            MEDIA_ERR_LOG("Failed to get count, err: %{public}d", err);
            return;
        }
        if (count > 0) {
            list<Uri> sendUris = UpdateAnalysisAlbumsForCloudSync(rdbStore, resultSet, fileIds);
            AddNewNotify(newHandleData, sendUris);
        }
    }

    if (nextHandler_ != nullptr) {
        nextHandler_->Handle(newHandleData);
    }
    refreshAlbumsFunc_(true);
}
} //namespace Media
} //namespace OHOS
