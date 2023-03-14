/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Thumbnail"

#include "ithumbnail_helper.h"

#include "ability_manager_client.h"
#include "hitrace_meter.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "thumbnail_const.h"
#include "thumbnail_utils.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
shared_ptr<AbsSharedResultSet> IThumbnailHelper::QueryThumbnailInfo(ThumbRdbOpt &opts,
    ThumbnailData &outData, int &err)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return nullptr;
    }
    string filesTableName = MEDIALIBRARY_TABLE;
    int errCode = E_ERR;
    if (!opts.networkId.empty()) {
        filesTableName = opts.store->ObtainDistributedTableName(opts.networkId, MEDIALIBRARY_TABLE, errCode);
    }

    MEDIA_DEBUG_LOG("Get filesTableName [ %{public}s ] id [ %{public}s ]", filesTableName.c_str(), opts.row.c_str());
    opts.table = filesTableName;
    shared_ptr<AbsSharedResultSet> rdbSet = ThumbnailUtils::QueryThumbnailInfo(opts, outData, err);
    if (rdbSet == nullptr) {
        MEDIA_ERR_LOG("QueryThumbnailInfo Faild [ %{public}d ]", err);
        return nullptr;
    }
    return rdbSet;
}

void IThumbnailHelper::CreateLcd(AsyncTaskData* data)
{
    GenerateAsyncTaskData* taskData = static_cast<GenerateAsyncTaskData*>(data);
    DoCreateLcd(taskData->opts, taskData->thumbnailData, true);
}

void IThumbnailHelper::CreateThumbnail(AsyncTaskData* data)
{
    GenerateAsyncTaskData* taskData = static_cast<GenerateAsyncTaskData*>(data);
    DoCreateThumbnail(taskData->opts, taskData->thumbnailData, true);
}

void IThumbnailHelper::AddAsyncTask(MediaLibraryExecute executor, ThumbRdbOpt &opts, ThumbnailData &data, bool isFront)
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_DEBUG_LOG("IThumbnailHelper::AddAsyncTask asyncWorker is null");
        return;
    }
    GenerateAsyncTaskData* taskData = new (nothrow)GenerateAsyncTaskData();
    if (taskData == nullptr) {
        MEDIA_DEBUG_LOG("IThumbnailHelper::GenerateAsyncTaskData taskData is null");
        return;
    }
    taskData->opts = opts;
    taskData->thumbnailData = data;

    shared_ptr<MediaLibraryAsyncTask> generateAsyncTask = make_shared<MediaLibraryAsyncTask>(executor, taskData);
    asyncWorker->AddTask(generateAsyncTask, isFront);
}

ThumbnailWait::ThumbnailWait(bool release) : needRelease_(release)
{}

ThumbnailWait::~ThumbnailWait()
{
    if (needRelease_) {
        Notify();
    }
}

ThumbnailMap ThumbnailWait::thumbnailMap_;
std::shared_mutex ThumbnailWait::mutex_;

static bool WaitFor(const shared_ptr<SyncStatus>& thumbnailWait, int waitMs, unique_lock<mutex> &lck)
{
    bool ret = thumbnailWait->cond_.wait_for(lck, chrono::milliseconds(waitMs),
        [thumbnailWait]() { return thumbnailWait->isSyncComplete_; });
    if (!ret) {
        MEDIA_INFO_LOG("IThumbnailHelper::Wait wait for lock timeout");
    }
    return ret;
}

WaitStatus ThumbnailWait::InsertAndWait(const string &id, bool isLcd)
{
    id_ = id;

    if (isLcd) {
        id_ += THUMBNAIL_LCD_END_SUFFIX;
    }
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        unique_lock<mutex> lck(thumbnailWait->mtx_);
        writeLck.unlock();
        bool ret = WaitFor(thumbnailWait, WAIT_FOR_MS, lck);
        if (ret) {
            return WaitStatus::WAIT_SUCCESS;
        } else {
            return WaitStatus::TIMEOUT;
        }
    } else {
        shared_ptr<SyncStatus> thumbnailWait = make_shared<SyncStatus>();
        thumbnailMap_.insert(ThumbnailMap::value_type(id_, thumbnailWait));
        return WaitStatus::INSERT;
    }
}

void ThumbnailWait::CheckAndWait(const string &id, bool isLcd)
{
    id_ = id;

    if (isLcd) {
        id_ += THUMBNAIL_LCD_END_SUFFIX;
    }
    shared_lock<shared_mutex> readLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        unique_lock<mutex> lck(thumbnailWait->mtx_);
        readLck.unlock();
        WaitFor(thumbnailWait, WAIT_FOR_MS, lck);
    }
}

void ThumbnailWait::Notify()
{
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        thumbnailMap_.erase(iter);
        {
            unique_lock<mutex> lck(thumbnailWait->mtx_);
            writeLck.unlock();
            thumbnailWait->isSyncComplete_ = true;
        }
        thumbnailWait->cond_.notify_all();
    }
}

bool IThumbnailHelper::DoCreateLcd(ThumbRdbOpt &opts, ThumbnailData &data, bool force)
{
    ThumbnailWait thumbnailWait(true);
    auto ret = thumbnailWait.InsertAndWait(data.id, true);
    int err = 0;
    if (ret == WaitStatus::WAIT_SUCCESS) {
        ThumbnailUtils::QueryThumbnailInfo(opts, data, err);
        return true;
    }

    if (!opts.networkId.empty()) {
        return false;
    }

    if (data.dateModified == 0) {
        ThumbnailUtils::QueryThumbnailInfo(opts, data, err);
    }

    if (!ThumbnailUtils::GenLcdKey(data)) {
        MEDIA_ERR_LOG("GenLcdKey faild");
        return false;
    }

    if (!ThumbnailUtils::IsImageExist(data.lcdKey, opts.networkId, opts.kvStore)) {
        if (!ThumbnailUtils::LoadSourceImage(data)) {
            MEDIA_ERR_LOG("LoadSourceImage faild");
            return false;
        }
        if (!ThumbnailUtils::CreateLcdData(data, opts.size)) {
            MEDIA_ERR_LOG("CreateLcdData faild");
            return false;
        }

        if (ThumbnailUtils::SaveLcdData(data, opts.networkId, opts.kvStore) != Status::SUCCESS) {
            MEDIA_ERR_LOG("SaveLcdData faild");
            return false;
        }
    } else {
        return true;
    }

    data.lcd.clear();
    if ((data.dateModified == 0) || force) {
        ThumbnailUtils::DeleteOriginImage(opts, data);
    }
    if (!ThumbnailUtils::UpdateThumbnailInfo(opts, data, err)) {
        MEDIA_INFO_LOG("UpdateThumbnailInfo faild err : %{public}d", err);
        return false;
    }

    return true;
}

bool IThumbnailHelper::DoCreateThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, bool force)
{
    ThumbnailWait thumbnailWait(true);
    auto ret = thumbnailWait.InsertAndWait(data.id, true);
    int err = 0;
    if (ret == WaitStatus::WAIT_SUCCESS) {
        ThumbnailUtils::QueryThumbnailInfo(opts, data, err);
        return true;
    }
    if (!opts.networkId.empty()) {
        return false;
    }

    if (data.dateModified == 0) {
        ThumbnailUtils::QueryThumbnailInfo(opts, data, err);
    }

    if (!ThumbnailUtils::GenThumbnailKey(data)) {
        MEDIA_ERR_LOG("GenThumbnailKey faild");
        return false;
    }

    if (!ThumbnailUtils::IsImageExist(data.thumbnailKey, opts.networkId, opts.kvStore)) {
        if (!ThumbnailUtils::LoadSourceImage(data)) {
            MEDIA_ERR_LOG("LoadSourceImage faild");
            return false;
        }
        if (!ThumbnailUtils::CreateThumbnailData(data)) {
            MEDIA_ERR_LOG("CreateThumbnailData faild");
            return false;
        }

        if (ThumbnailUtils::SaveThumbnailData(data, opts.networkId, opts.kvStore) != Status::SUCCESS) {
            MEDIA_ERR_LOG("SaveThumbnailData faild");
            return false;
        }
    }

    data.thumbnail.clear();
    if ((data.dateModified == 0) || force) {
        ThumbnailUtils::DeleteOriginImage(opts, data);
    }
    if (!ThumbnailUtils::UpdateThumbnailInfo(opts, data, err)) {
        MEDIA_ERR_LOG("UpdateThumbnailInfo faild, %{public}d", err);
        return false;
    }

    return true;
}

bool IThumbnailHelper::DoThumbnailSync(ThumbRdbOpt &opts, ThumbnailData &outData)
{
    ThumbnailConnection *conn = new (nothrow) ThumbnailConnection;
    if (conn == nullptr) {
        return false;
    }
    sptr<AAFwk::IAbilityConnection> callback(conn);
    int ret = conn->GetRemoteDataShareHelper(opts, callback);
    if (ret != E_OK) {
        return false;
    }

    vector<string> devices = { opts.networkId };
    opts.table = MEDIALIBRARY_TABLE;
    if (ThumbnailUtils::SyncPullTable(opts, devices, true)) {
        MEDIA_INFO_LOG("GetThumbnailPixelMap SyncPullTable FALSE");
        return false;
    }
    shared_ptr<AbsSharedResultSet> resultSet = QueryThumbnailInfo(opts, outData, ret);
    if ((resultSet == nullptr)) {
        MEDIA_ERR_LOG("QueryThumbnailInfo Faild [ %{public}d ]", ret);
        return false;
    }
    return true;
}

void ThumbnailConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("OnAbilityConnectDone failed, remote is nullptr");
        return;
    }
    {
        unique_lock<mutex> lock(status_.mtx_);
        dataShareProxy_ = iface_cast<DataShare::DataShareProxy>(remoteObject);
    }
    status_.cond_.notify_all();
}

void ThumbnailConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    MEDIA_DEBUG_LOG("called begin %{public}d", resultCode);
    unique_lock<mutex> lock(status_.mtx_);
    dataShareProxy_ = nullptr;
}

int32_t ThumbnailConnection::GetRemoteDataShareHelper(ThumbRdbOpt &opts, sptr<AAFwk::IAbilityConnection> &callback)
{
    if ((opts.context == nullptr)) {
        MEDIA_ERR_LOG("context nullptr");
        return E_ERR;
    }

    AAFwk::Want want;
    want.SetElementName(BUNDLE_NAME, "DataShareExtAbility");
    want.SetDeviceId(opts.networkId);
    auto err = AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, callback, opts.context->GetToken());
    if (err != E_OK) {
        MEDIA_ERR_LOG("ConnectAbility failed %{public}d", err);
        return err;
    }
    unique_lock<mutex> lock(status_.mtx_);
    if (status_.cond_.wait_for(lock, chrono::seconds(WAIT_FOR_SECOND),
        [this] { return dataShareProxy_ != nullptr; })) {
        MEDIA_DEBUG_LOG("All Wait connect success.");
    } else {
        MEDIA_ERR_LOG("All Wait connect timeout.");
        return E_THUMBNAIL_CONNECT_TIMEOUT;
    }

    Uri distriuteGenUri(opts.uri + "/" + DISTRIBUTE_THU_OPRN_CREATE);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_URI, opts.uri);
    auto ret = dataShareProxy_->Insert(distriuteGenUri, valuesBucket);
    MEDIA_DEBUG_LOG("called end ret = %{public}d", ret);
    return ret;
}
} // namespace Media
} // namespace OHOS
