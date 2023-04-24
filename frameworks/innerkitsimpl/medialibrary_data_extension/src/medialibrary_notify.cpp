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
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "uri.h"

using namespace std;

namespace OHOS::Media {
using ChangeType = AAFwk::ChangeInfo::ChangeType;
using NotifyDataMap = unordered_map<NotifyType, list<Uri>>;
shared_ptr<MediaLibraryNotify> MediaLibraryNotify::instance_;
mutex MediaLibraryNotify::mutex_;
unordered_map<string, NotifyDataMap> MediaLibraryNotify::nfListMap_ = {};
Utils::Timer MediaLibraryNotify::timer_("on_notify");

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

MediaLibraryNotify::~MediaLibraryNotify() = default;

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

static int SendAlbumSub(const Uri &notifyUri, ChangeType type, list<Uri> &uris)
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
    if (type == static_cast<ChangeType>(NotifyType::NOTIFY_ALBUM_ADD_ASSERT)) {
        type = ChangeType::INSERT;
    } else {
        type = ChangeType::DELETE;
    }
    return obsMgrClient->NotifyChangeExt({type, {notifyUri}, uBuf, parcel.GetDataSize()});
}

static int SolveAlbumUri(const Uri &notifyUri, NotifyType type, list<Uri> &uris)
{
    auto obsMgrClient = AAFwk::DataObsMgrClient::GetInstance();
    if ((type == NotifyType::NOTIFY_ALBUM_ADD_ASSERT) || (type == NotifyType::NOTIFY_ALBUM_REMOVE_ASSET)) {
        return SendAlbumSub(notifyUri, static_cast<ChangeType>(type), uris);
    } else {
        return obsMgrClient->NotifyChangeExt({static_cast<ChangeType>(type), uris});
    }
}

static void PushNotifyDataMap(const string &uri, NotifyDataMap notifyDataMap)
{
    int ret;
    for (auto &[type, uris] : notifyDataMap) {
        if (uri.find(MEDIALIBRARY_ALBUM_URI) != string::npos) {
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
    lock_guard<mutex> lock(MediaLibraryNotify::mutex_);
    if (MediaLibraryNotify::nfListMap_.empty()) {
        return;
    }
    unordered_map<string, NotifyDataMap> tmpNfListMap;
    {
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
        "notifyType = %{private}d", keyUri.c_str(), uri.ToString().c_str(), taskData->notifyType);
    lock_guard<mutex> lock(MediaLibraryNotify::mutex_);
    if (MediaLibraryNotify::nfListMap_.count(keyUri) == 0) {
        sendUris.emplace_back(uri);
        notifyDataMap.insert(make_pair(taskData->notifyType, sendUris));
        MediaLibraryNotify::nfListMap_.insert(make_pair(keyUri, notifyDataMap));
    } else {
        auto iter = MediaLibraryNotify::nfListMap_.find(keyUri);
        if (iter->second.count(taskData->notifyType) == 0) {
            sendUris.emplace_back(uri);
            iter->second.insert(make_pair(taskData->notifyType, sendUris));
        } else {
            auto haveIter = find_if(
                iter->second.at(taskData->notifyType).begin(),
                iter->second.at(taskData->notifyType).end(),
                [uri](const Uri &listUri) { return uri.Equals(listUri); });
            if (haveIter == iter->second.at(taskData->notifyType).end()) {
                iter->second.find(taskData->notifyType)->second.emplace_back(uri);
            }
        }
    }
}

static void AddNfListMap(AsyncTaskData *data)
{
    if (data == nullptr) {
        return;
    }
    auto* taskData = static_cast<NotifyTaskData*>(data);
    if ((taskData->notifyType == NotifyType::NOTIFY_ALBUM_ADD_ASSERT) ||
        (taskData->notifyType == NotifyType::NOTIFY_ALBUM_REMOVE_ASSET)) {
        if (taskData->albumId > 0) {
            AddNotify(taskData->uri, MEDIALIBRARY_ALBUM_URI + "/" + to_string(taskData->albumId), taskData);
        } else {
            list<string> albumUriList;
            string id = MediaLibraryDataManagerUtils::GetIdFromUri(taskData->uri);
            int err = MediaLibraryObjectUtils::GetAlbumUrisById(id, albumUriList);
            CHECK_AND_RETURN_LOG(err == E_OK, "Fail to get albumId");
            for (string uri : albumUriList) {
                AddNotify(taskData->uri, uri, taskData);
            }
        }
    } else {
        string typeUri = MediaLibraryDataManagerUtils::GetTypeUriByUri(taskData->uri);
        AddNotify(taskData->uri, typeUri, taskData);
    }
}

int32_t MediaLibraryNotify::Init()
{
    MediaLibraryNotify::timer_.Register(PushNotification, MNOTIFY_TIME_INTERVAL);
    MediaLibraryNotify::timer_.Setup();
    return E_OK;
}

int32_t MediaLibraryNotify::Notify(const string &uri, const NotifyType notifyType, const int albumId)
{
    if (MediaLibraryNotify::nfListMap_.size() > MAX_NOTIFY_LIST_SIZE) {
        MediaLibraryNotify::timer_.Shutdown();
        PushNotification();
        MediaLibraryNotify::timer_.Register(PushNotification, MNOTIFY_TIME_INTERVAL);
        MediaLibraryNotify::timer_.Setup();
    }
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_RET_LOG(asyncWorker != nullptr, E_ASYNC_WORKER_IS_NULL, "AsyncWorker is null");
    auto *taskData = new (nothrow) NotifyTaskData();
    CHECK_AND_RETURN_RET_LOG(taskData != nullptr, E_NOTIFY_TASK_DATA_IS_NULL, "taskData is null");
    MEDIA_ERR_LOG("Notify ,uri = %{private}s, notifyType = %{private}d, albumId = %{private}d",
        uri.c_str(), notifyType, albumId);
    taskData->uri = uri;
    taskData->notifyType = notifyType;
    taskData->albumId = albumId;
    shared_ptr<MediaLibraryAsyncTask> notifyAsyncTask = make_shared<MediaLibraryAsyncTask>(AddNfListMap, taskData);
    if (notifyAsyncTask != nullptr) {
        asyncWorker->AddTask(notifyAsyncTask, false);
    }
    return E_OK;
}
} // namespace OHOS::Media