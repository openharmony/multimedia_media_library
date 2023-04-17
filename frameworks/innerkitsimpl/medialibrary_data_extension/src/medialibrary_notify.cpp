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
#include "media_log.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "uri.h"

using namespace std;

namespace OHOS::Media {
using ChangeType = AAFwk::ChangeInfo::ChangeType;
using NotifyDataMap = unordered_map<ChangeType, list<Uri>>;
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
        MEDIA_ERR_LOG("Failed to write uri list length, list size = %{private}u", uris.size());
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
    return obsMgrClient->NotifyChangeExt({type, {notifyUri}, uBuf, parcel.GetDataSize()});
}

static int SolveAlbumUri(const Uri &notifyUri, ChangeType type, list<Uri> &uris)
{
    auto obsMgrClient = AAFwk::DataObsMgrClient::GetInstance();
    auto iter = find_if(uris.begin(), uris.end(), [notifyUri](const Uri &listUri) {
        return notifyUri.Equals(listUri);
    });
    int ret = 0;
    if (iter != uris.end()) {
        uris.remove(notifyUri);
        ret = obsMgrClient->NotifyChangeExt({type, {notifyUri}});
        if (ret != E_OK) {
            MEDIA_ERR_LOG("NotifyChangeExt failed, errorCode = %{public}d", ret);
            return E_NOTIFY_CHANGE_EXT_FAILED;
        }
    }
    return SendAlbumSub(notifyUri, type, uris);
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
            ret = obsMgrClient->NotifyChangeExt({type, uris});
        }
        if (ret != E_OK) {
            MEDIA_ERR_LOG("PushNotification failed, errorCode = %{public}d", ret);
        }
    }
    return;
}

static void PushNotification()
{
    if (MediaLibraryNotify::nfListMap_.empty()) {
        return;
    }
    unordered_map<string, NotifyDataMap> tmpNfListMap;
    {
        lock_guard<mutex> lock(MediaLibraryNotify::mutex_);
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

static void AddNotify(const shared_ptr<FileAsset> &fileAsset, const string &strUri, NotifyTaskData* taskData)
{
    NotifyDataMap notifyDataMap;
    list<Uri> sendUris;
    Uri uri(fileAsset->GetUri());
    MEDIA_DEBUG_LOG("AddNotify ,strUri = %{private}s, uri = %{private}s, "
        "changeType = %{private}d", strUri.c_str(), uri.ToString().c_str(), taskData->changeType);
    lock_guard<mutex> lock(MediaLibraryNotify::mutex_);
    if (MediaLibraryNotify::nfListMap_.count(strUri) == 0) {
        sendUris.emplace_back(uri);
        notifyDataMap.insert(make_pair(taskData->changeType, sendUris));
        MediaLibraryNotify::nfListMap_.insert(make_pair(strUri, notifyDataMap));
    } else {
        auto iter = MediaLibraryNotify::nfListMap_.find(strUri);
        if (iter->second.count(taskData->changeType) == 0) {
            sendUris.emplace_back(uri);
            iter->second.insert(make_pair(taskData->changeType, sendUris));
            auto tmp = MediaLibraryNotify::nfListMap_.at(strUri);
        } else {
            auto haveIter = find_if(
                iter->second.at(taskData->changeType).begin(),
                iter->second.at(taskData->changeType).end(),
                [uri](const Uri &listUri) { return uri.Equals(listUri); });
            if (haveIter == iter->second.at(taskData->changeType).end()) {
                iter->second.find(taskData->changeType)->second.emplace_back(uri);
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
    shared_ptr<FileAsset> fileAsset = MediaLibraryObjectUtils::GetFileAssetFromId(taskData->strId);
    string typeUri = MediaLibraryDataManagerUtils::GetMediaTypeUri(fileAsset->GetMediaType());
    AddNotify(fileAsset, typeUri, taskData);
}

int32_t MediaLibraryNotify::Init()
{
    MediaLibraryNotify::timer_.Register(PushNotification, MNOTIFY_TIME_INTERVAL);
    MediaLibraryNotify::timer_.Setup();
    return E_OK;
}

int32_t MediaLibraryNotify::Notify(const string &strId, ChangeType changeType)
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
    taskData->strId = strId;
    taskData->changeType = changeType;
    shared_ptr<MediaLibraryAsyncTask> notifyAsyncTask = make_shared<MediaLibraryAsyncTask>(AddNfListMap, taskData);
    if (notifyAsyncTask != nullptr) {
        asyncWorker->AddTask(notifyAsyncTask, false);
    }
    return E_OK;
}

int32_t MediaLibraryNotify::Notify(const shared_ptr<FileAsset> &closeAsset)
{
    bool isCreateFile = false;
    if (closeAsset->GetDateAdded() == closeAsset->GetDateModified() ||
        closeAsset->GetDateModified() == 0) {
        isCreateFile = true;
    }
    if (isCreateFile) {
        return Notify(to_string(closeAsset->GetId()), ChangeType::INSERT);
    }
    return Notify(to_string(closeAsset->GetId()), ChangeType::UPDATE);
}
} // namespace OHOS::Media