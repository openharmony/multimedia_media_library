/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#define MLOG_TAG "FileNotify"
#include "medialibrary_notify.h"
#include "data_ability_helper_impl.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "result_set_utils.h"
#include "uri.h"

using namespace std;

namespace OHOS::Media {
using ChangeType = AAFwk::ChangeInfo::ChangeType;
using NotifyDataMap = unordered_map<NotifyType, list<Uri>>;
shared_ptr<MediaLibraryNotify> MediaLibraryNotify::instance_;
mutex MediaLibraryNotify::mutex_;
unordered_map<string, NotifyDataMap> MediaLibraryNotify::nfListMap_ = {};
Utils::Timer MediaLibraryNotify::timer_("on_notify");
uint32_t MediaLibraryNotify::timerId_ = 0;

shared_ptr<MediaLibraryNotify> MediaLibraryNotify::GetInstance()
{
    if (instance_ != nullptr) {
        return instance_;
    }
    lock_guard<mutex> lock(mutex_);
    if (instance_ == nullptr) {
        instance_ = shared_ptr<MediaLibraryNotify>(new MediaLibraryNotify());
        if (instance_ == nullptr) {
            MEDIA_ERR_LOG("GetInstance nullptr");
            return instance_;
        }
        instance_->Init();
    }
    return instance_;
}
MediaLibraryNotify::MediaLibraryNotify() = default;

MediaLibraryNotify::~MediaLibraryNotify()
{
    timer_.Shutdown();
    timer_.Unregister(timerId_);
};

static bool SolveUris(const list<Uri> &uris, Parcel &parcel)
{
    if (uris.size() > numeric_limits<uint32_t>::max() ||
        !parcel.WriteUint32(static_cast<uint32_t>(uris.size()))) {
        MEDIA_ERR_LOG("Failed to write uri list length, list size = %{private}zu", uris.size());
        return false;
    }
    for (auto const &uri : uris) {
        if (!parcel.WriteString(uri.ToString())) {
            MEDIA_ERR_LOG("Failed to write strUri uri = %{private}s", uri.ToString().c_str());
            return false;
        }
    }
    return true;
}

static int SendAlbumSub(const Uri &notifyUri, NotifyType type, list<Uri> &uris)
{
    Parcel parcel;
    CHECK_AND_RETURN_RET_LOG(SolveUris(uris, parcel), E_SOLVE_URIS_FAILED, "SolveUris failed");
    auto obsMgrClient = AAFwk::DataObsMgrClient::GetInstance();
    uintptr_t buf = parcel.GetData();
    if (parcel.GetDataSize() == 0) {
        MEDIA_ERR_LOG("NotifyChangeExt parcel.GetDataSize failed");
        return E_PARCEL_GET_SIZE_FAILED;
    }
    auto *uBuf = new (std::nothrow) uint8_t[parcel.GetDataSize()];
    int ret = memcpy_s(uBuf, parcel.GetDataSize(), reinterpret_cast<uint8_t *>(buf), parcel.GetDataSize());
    if (ret != 0) {
        MEDIA_ERR_LOG("Parcel data copy failed, err = %{public}d", ret);
    }
    ChangeType changeType;
    if (type == NotifyType::NOTIFY_ALBUM_ADD_ASSET) {
        changeType = ChangeType::INSERT;
    } else {
        changeType = ChangeType::DELETE;
    }
    return obsMgrClient->NotifyChangeExt({changeType, {notifyUri}, uBuf, parcel.GetDataSize()});
}

static int SolveAlbumUri(const Uri &notifyUri, NotifyType type, list<Uri> &uris)
{
    auto obsMgrClient = AAFwk::DataObsMgrClient::GetInstance();
    if ((type == NotifyType::NOTIFY_ALBUM_ADD_ASSET) || (type == NotifyType::NOTIFY_ALBUM_REMOVE_ASSET)) {
        return SendAlbumSub(notifyUri, type, uris);
    } else {
        return obsMgrClient->NotifyChangeExt({static_cast<ChangeType>(type), uris});
    }
}

static void PushNotifyDataMap(const string &uri, NotifyDataMap notifyDataMap)
{
    int ret;
    for (auto &[type, uris] : notifyDataMap) {
        if (uri.find(PhotoAlbumColumns::ALBUM_URI_PREFIX) != string::npos) {
            Uri notifyUri = Uri(uri);
            ret = SolveAlbumUri(notifyUri, type, uris);
        } else {
            auto obsMgrClient = AAFwk::DataObsMgrClient::GetInstance();
            ret = obsMgrClient->NotifyChangeExt({static_cast<ChangeType>(type), uris});
        }
        if (ret != E_OK) {
            MEDIA_ERR_LOG("PushNotification failed, errorCode = %{public}d", ret);
        }
    }
    return;
}

static void PushNotification()
{
    unordered_map<string, NotifyDataMap> tmpNfListMap;
    {
        lock_guard<mutex> lock(MediaLibraryNotify::mutex_);
        if (MediaLibraryNotify::nfListMap_.empty()) {
            return;
        }
        MediaLibraryNotify::nfListMap_.swap(tmpNfListMap);
        MediaLibraryNotify::nfListMap_.clear();
    }
    for (auto &[uri, notifyDataMap] : tmpNfListMap) {
        if (notifyDataMap.empty()) {
            continue;
        }
        PushNotifyDataMap(uri, notifyDataMap);
    }
}

static void AddNotify(const string &srcUri, const string &keyUri, NotifyTaskData* taskData)
{
    NotifyDataMap notifyDataMap;
    list<Uri> sendUris;
    Uri uri(srcUri);
    MEDIA_DEBUG_LOG("AddNotify ,keyUri = %{private}s, uri = %{private}s, "
        "notifyType = %{private}d", keyUri.c_str(), uri.ToString().c_str(), taskData->notifyType_);
    lock_guard<mutex> lock(MediaLibraryNotify::mutex_);
    if (MediaLibraryNotify::nfListMap_.count(keyUri) == 0) {
        sendUris.emplace_back(uri);
        notifyDataMap.insert(make_pair(taskData->notifyType_, sendUris));
        MediaLibraryNotify::nfListMap_.insert(make_pair(keyUri, notifyDataMap));
    } else {
        auto iter = MediaLibraryNotify::nfListMap_.find(keyUri);
        if (iter->second.count(taskData->notifyType_) == 0) {
            sendUris.emplace_back(uri);
            iter->second.insert(make_pair(taskData->notifyType_, sendUris));
        } else {
            auto haveIter = find_if(
                iter->second.at(taskData->notifyType_).begin(),
                iter->second.at(taskData->notifyType_).end(),
                [uri](const Uri &listUri) { return uri.Equals(listUri); });
            if (haveIter == iter->second.at(taskData->notifyType_).end()) {
                iter->second.find(taskData->notifyType_)->second.emplace_back(uri);
            }
        }
    }
}

static int32_t GetAlbumsById(const string &fileId, list<string> &albumIdList)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    MediaLibraryCommand queryAlbumMapCmd(OperationObject::PHOTO_MAP, OperationType::QUERY);
    queryAlbumMapCmd.GetAbsRdbPredicates()->EqualTo(PhotoMap::ASSET_ID, fileId);
    auto resultSet = uniStore->Query(queryAlbumMapCmd, {PhotoMap::ALBUM_ID});
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("GetAlbumsById failed");
        return E_INVALID_FILEID;
    }
    int32_t count = -1;
    int32_t ret = resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Failed to get count");
    if (count <= 0) {
        return E_OK;
    }
    ret = resultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Failed to GoToFirstRow");
    do {
        int32_t albumId = get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoMap::ALBUM_ID, resultSet,
            TYPE_INT32));
        albumIdList.emplace_back(to_string(albumId));
    } while (!resultSet->GoToNextRow());
    return E_OK;
}

static void HandleAlbumNotify(NotifyTaskData *taskData)
{
    list<string> albumIdList;
    string id = MediaFileUtils::GetIdFromUri(taskData->uri_);
    int err = GetAlbumsById(id, albumIdList);
    CHECK_AND_RETURN_LOG(err == E_OK, "Fail to get albumId");
    for (const string &id : albumIdList) {
        AddNotify(taskData->uri_, PhotoAlbumColumns::ALBUM_URI_PREFIX + id, taskData);
    }

    if (!taskData->hiddenOnly_) {
        return;
    }
    NotifyType hiddenAlbumsNotifyType = taskData->notifyType_;
    if (taskData->notifyType_ == NotifyType::NOTIFY_ALBUM_ADD_ASSET) {
        hiddenAlbumsNotifyType = NotifyType::NOTIFY_ALBUM_REMOVE_ASSET;
    } else if (taskData->notifyType_ == NotifyType::NOTIFY_ALBUM_REMOVE_ASSET) {
        hiddenAlbumsNotifyType = NotifyType::NOTIFY_ALBUM_ADD_ASSET;
    }
    taskData->notifyType_ = hiddenAlbumsNotifyType;
    for (const string &id : albumIdList) {
        AddNotify(taskData->uri_, PhotoAlbumColumns::HIDDEN_ALBUM_URI_PREFIX + id, taskData);
    }
}

static void AddNfListMap(AsyncTaskData *data)
{
    if (data == nullptr) {
        return;
    }
    auto* taskData = static_cast<NotifyTaskData*>(data);
    if ((taskData->notifyType_ == NotifyType::NOTIFY_ALBUM_ADD_ASSET) ||
        (taskData->notifyType_ == NotifyType::NOTIFY_ALBUM_REMOVE_ASSET)) {
        if (taskData->albumId_ > 0) {
            AddNotify(taskData->uri_,
                PhotoAlbumColumns::ALBUM_URI_PREFIX  + to_string(taskData->albumId_), taskData);
        } else {
            HandleAlbumNotify(taskData);
        }
    } else {
        string typeUri = MediaLibraryDataManagerUtils::GetTypeUriByUri(taskData->uri_);
        AddNotify(taskData->uri_, typeUri, taskData);
    }
}

int32_t MediaLibraryNotify::Init()
{
    MediaLibraryNotify::timerId_ = MediaLibraryNotify::timer_.Register(PushNotification, MNOTIFY_TIME_INTERVAL);
    MediaLibraryNotify::timer_.Setup();
    return E_OK;
}

int32_t MediaLibraryNotify::Notify(const string &uri, const NotifyType notifyType, const int albumId,
    const bool hiddenOnly)
{
    if (MediaLibraryNotify::nfListMap_.size() > MAX_NOTIFY_LIST_SIZE) {
        MediaLibraryNotify::timer_.Shutdown();
        PushNotification();
        MediaLibraryNotify::timer_.Register(PushNotification, MNOTIFY_TIME_INTERVAL);
        MediaLibraryNotify::timer_.Setup();
    }
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_RET_LOG(asyncWorker != nullptr, E_ASYNC_WORKER_IS_NULL, "AsyncWorker is null");
    auto *taskData = new (nothrow) NotifyTaskData(uri, notifyType, albumId, hiddenOnly);
    CHECK_AND_RETURN_RET_LOG(taskData != nullptr, E_NOTIFY_TASK_DATA_IS_NULL, "taskData is null");
    MEDIA_DEBUG_LOG("Notify ,uri = %{private}s, notifyType = %{private}d, albumId = %{private}d",
        uri.c_str(), notifyType, albumId);
    shared_ptr<MediaLibraryAsyncTask> notifyAsyncTask = make_shared<MediaLibraryAsyncTask>(AddNfListMap, taskData);
    if (notifyAsyncTask != nullptr) {
        asyncWorker->AddTask(notifyAsyncTask, true);
    }
    return E_OK;
}

int32_t MediaLibraryNotify::Notify(const shared_ptr<FileAsset> &closeAsset)
{
    bool isCreateFile = false;
    if (closeAsset->GetDateModified() == 0) {
        isCreateFile = true;
    }
    if (closeAsset->GetMediaType() == MediaType::MEDIA_TYPE_IMAGE ||
        closeAsset->GetMediaType() == MediaType::MEDIA_TYPE_VIDEO) {
        if (isCreateFile) {
            return Notify(PhotoColumn::PHOTO_URI_PREFIX + to_string(closeAsset->GetId()), NotifyType::NOTIFY_ADD);
        }
        return Notify(PhotoColumn::PHOTO_URI_PREFIX + to_string(closeAsset->GetId()), NotifyType::NOTIFY_UPDATE);
    } else if (closeAsset->GetMediaType() == MediaType::MEDIA_TYPE_AUDIO) {
        if (isCreateFile) {
            return Notify(AudioColumn::AUDIO_URI_PREFIX + to_string(closeAsset->GetId()), NotifyType::NOTIFY_ADD);
        }
        return Notify(AudioColumn::AUDIO_URI_PREFIX + to_string(closeAsset->GetId()), NotifyType::NOTIFY_UPDATE);
    } else {
        return E_CHECK_MEDIATYPE_FAIL;
    }
}

int32_t MediaLibraryNotify::GetDefaultAlbums(std::unordered_map<PhotoAlbumSubType, int> &outAlbums)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    MediaLibraryCommand queryAlbumMapCmd(OperationObject::PHOTO_ALBUM, OperationType::QUERY);
    queryAlbumMapCmd.GetAbsRdbPredicates()->EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SYSTEM));
    CHECK_AND_RETURN_RET_LOG(uniStore != nullptr, E_HAS_DB_ERROR, "UniStore is nullptr!");
    auto resultSet = uniStore->Query(queryAlbumMapCmd,
        {PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_SUBTYPE});
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int32_t count = -1;
    int32_t ret = resultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Failed to get count");
    ret = resultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "Failed to GoToFirstRow");
    do {
        int32_t albumId = get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_ID, resultSet,
            TYPE_INT32));
        int32_t albumSubType = get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_SUBTYPE,
            resultSet, TYPE_INT32));
        MEDIA_INFO_LOG("GetDefaultAlbums albumId: %{public}d, albumSubType: %{public}d", albumId, albumSubType);
        outAlbums.insert(make_pair(static_cast<PhotoAlbumSubType>(albumSubType), albumId));
    } while (!resultSet->GoToNextRow());
    return E_OK;
}

int32_t MediaLibraryNotify::GetAlbumIdBySubType(const PhotoAlbumSubType subType)
{
    int errCode = E_OK;
    if (defaultAlbums_.size() == 0) {
        errCode = GetDefaultAlbums(defaultAlbums_);
    }
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Failed to GetDefaultAlbums");
    if (defaultAlbums_.count(subType) == 0) {
        return E_ERR;
    }
    return defaultAlbums_.find(subType)->second;
}

static void GetNotifyUri(shared_ptr<NativeRdb::ResultSet> &resultSet, vector<string> &notifyUris)
{
    int32_t fileId = MediaLibraryRdbStore::GetInt(resultSet, PhotoColumn::MEDIA_ID);
    string path = MediaLibraryRdbStore::GetString(resultSet, PhotoColumn::MEDIA_FILE_PATH);
    string displayName = MediaLibraryRdbStore::GetString(resultSet, PhotoColumn::MEDIA_NAME);
    string notifyUri = MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(fileId),
        MediaFileUtils::GetExtraUri(displayName, path));
    notifyUris.push_back(notifyUri);
}

void MediaLibraryNotify::GetNotifyUris(const AbsRdbPredicates &predicates, vector<string> &notifyUris)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetNotifyUris");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return;
    }
    auto resultSet = rdbStore->Query(predicates, {
        PhotoColumn::MEDIA_ID,
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_NAME
    });
    if (resultSet == nullptr) {
        return;
    }

    int32_t count = 0;
    int32_t err = resultSet->GetRowCount(count);
    if (err != E_OK || count <= 0) {
        MEDIA_WARN_LOG("Failed to get row count: %{public}d", err);
        return;
    }
    err = resultSet->GoToFirstRow();
    if (err != E_OK) {
        MEDIA_WARN_LOG("Failed to go to first row: %{public}d", err);
        return;
    }
    do {
        GetNotifyUri(resultSet, notifyUris);
        count--;
        if (count > 0) {
            err = resultSet->GoToNextRow();
            if (err < 0) {
                MEDIA_WARN_LOG("Failed to go to next row err: %{public}d", err);
                return;
            }
        }
    } while (count > 0);
}
} // namespace OHOS::Media
